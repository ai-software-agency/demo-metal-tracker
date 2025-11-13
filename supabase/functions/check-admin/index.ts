import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.39.3';
import { preflight, withCors } from '../_shared/util/cors.ts';

/**
 * Security Configuration
 * 
 * ADMIN_STEP_UP_MAX_AGE_SECONDS: Maximum age (in seconds) for authentication events
 *   before requiring reauthentication for admin privilege assertion. Default: 600 (10 minutes).
 *   This enforces recent authentication per OWASP A07:2021 and PCI DSS 8.3.
 * 
 * ADMIN_MFA_REQUIRED: Require MFA/step-up (AAL2) for admin checks. Default: true.
 *   When enabled, only sessions with aal2 or MFA indicators (totp, webauthn, etc.) pass.
 * 
 * ADMIN_MIN_AAL: Minimum Authenticator Assurance Level required for admin access.
 *   1 = Single factor, 2 = Multi-factor. Default: 2 (AAL2 required).
 */
const ADMIN_STEP_UP_MAX_AGE_SECONDS = parseInt(
  Deno.env.get('ADMIN_STEP_UP_MAX_AGE_SECONDS') || '600',
  10
);
const ADMIN_MFA_REQUIRED = Deno.env.get('ADMIN_MFA_REQUIRED') !== 'false'; // Default true
const ADMIN_MIN_AAL = parseInt(Deno.env.get('ADMIN_MIN_AAL') || '2', 10);

/**
 * Decode JWT payload without verification (signature already verified by Supabase auth)
 * @param token - JWT token string
 * @returns Decoded payload object or null on error
 */
function decodeJwtPayload(token: string): any {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }
    
    // Extract payload (second part)
    const payload = parts[1];
    
    // Convert base64url to base64
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    
    // Pad if needed
    const padded = base64.padEnd(base64.length + (4 - (base64.length % 4)) % 4, '=');
    
    // Decode base64
    const jsonString = atob(padded);
    
    return JSON.parse(jsonString);
  } catch (error) {
    console.error('JWT decode error:', error);
    return null;
  }
}

/**
 * Check if the JWT payload indicates AAL2 (multi-factor authentication)
 * 
 * AAL2 is confirmed by:
 * - payload.aal === 'aal2' (Supabase standard)
 * - OR payload.amr includes 'mfa', 'totp', 'webauthn', or other MFA methods
 * 
 * @param payload - Decoded JWT payload
 * @returns true if AAL2 is present
 */
function isAAL2(payload: any): boolean {
  if (!payload) return false;
  
  // Check explicit AAL claim
  if (payload.aal === 'aal2') {
    return true;
  }
  
  // Check authentication methods reference (amr)
  if (Array.isArray(payload.amr)) {
    const mfaMethods = ['mfa', 'totp', 'webauthn', 'otp', 'sms'];
    return payload.amr.some((method: string) => 
      mfaMethods.includes(method.toLowerCase())
    );
  }
  
  return false;
}

/**
 * Check if the authentication event is recent enough
 * 
 * Uses auth_time (preferred) or iat (issued at) claim to determine
 * when the user last authenticated. Requires authentication within
 * ADMIN_STEP_UP_MAX_AGE_SECONDS.
 * 
 * @param payload - Decoded JWT payload
 * @param maxAgeSeconds - Maximum age in seconds
 * @returns true if authentication is recent enough
 */
function isRecentAuth(payload: any, maxAgeSeconds: number): boolean {
  if (!payload) return false;
  
  const now = Math.floor(Date.now() / 1000);
  
  // Prefer auth_time (explicit authentication timestamp)
  // Fallback to iat (token issued at)
  const authTime = payload.auth_time || payload.iat;
  
  if (!authTime || typeof authTime !== 'number') {
    return false;
  }
  
  const age = now - authTime;
  return age >= 0 && age <= maxAgeSeconds;
}

/**
 * Validate step-up authentication requirements for admin access
 * 
 * Enforces:
 * 1. MFA/AAL2 requirement (if ADMIN_MFA_REQUIRED is true)
 * 2. Recent authentication (within ADMIN_STEP_UP_MAX_AGE_SECONDS)
 * 
 * @param payload - Decoded JWT payload
 * @returns { valid: boolean, reason?: string }
 */
function validateStepUp(payload: any): { valid: boolean; reason?: string } {
  // Check MFA requirement
  if (ADMIN_MFA_REQUIRED && ADMIN_MIN_AAL >= 2) {
    if (!isAAL2(payload)) {
      return {
        valid: false,
        reason: 'Multi-factor authentication (AAL2) required for admin access',
      };
    }
  }
  
  // Check recency requirement
  if (!isRecentAuth(payload, ADMIN_STEP_UP_MAX_AGE_SECONDS)) {
    return {
      valid: false,
      reason: `Recent authentication required (within ${ADMIN_STEP_UP_MAX_AGE_SECONDS}s)`,
    };
  }
  
  return { valid: true };
}

Deno.serve(async (req) => {
  // Handle CORS preflight requests with strict origin validation
  if (req.method === 'OPTIONS') {
    return preflight(req, ['POST', 'OPTIONS']);
  }

  try {
    // Get the authorization header from the request
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) {
      return withCors(
        req,
        new Response(
          JSON.stringify({ isAdmin: false, error: 'No authorization header' }),
          { status: 401, headers: { 'Content-Type': 'application/json' } }
        )
      );
    }

    // Extract bearer token
    const token = authHeader.replace(/^Bearer\s+/i, '');
    
    // Decode JWT payload to check step-up requirements
    const payload = decodeJwtPayload(token);
    if (!payload) {
      return withCors(
        req,
        new Response(
          JSON.stringify({ 
            isAdmin: false, 
            error: 'Invalid token format' 
          }),
          { status: 401, headers: { 'Content-Type': 'application/json' } }
        )
      );
    }
    
    // Validate step-up authentication (MFA + recency)
    const stepUpValidation = validateStepUp(payload);
    if (!stepUpValidation.valid) {
      console.warn('Admin check failed step-up validation:', {
        userId: payload.sub,
        reason: stepUpValidation.reason,
        aal: payload.aal,
        amr: payload.amr,
        auth_time: payload.auth_time,
        iat: payload.iat,
      });
      
      return withCors(
        req,
        new Response(
          JSON.stringify({
            isAdmin: false,
            mfa_required: true,
            reason: stepUpValidation.reason,
          }),
          { status: 401, headers: { 'Content-Type': 'application/json' } }
        )
      );
    }

    // Create Supabase client with the user's auth token
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      {
        global: {
          headers: { Authorization: authHeader },
        },
      }
    );

    // Get the authenticated user
    const {
      data: { user },
      error: userError,
    } = await supabaseClient.auth.getUser();

    if (userError || !user) {
      console.error('Error getting user:', userError);
      return withCors(
        req,
        new Response(
          JSON.stringify({ isAdmin: false, error: 'Unauthorized' }),
          { status: 401, headers: { 'Content-Type': 'application/json' } }
        )
      );
    }

    // Check if user has admin role using the has_role function
    const { data: isAdmin, error: roleError } = await supabaseClient.rpc('has_role', {
      _user_id: user.id,
      _role: 'admin',
    });

    if (roleError) {
      console.error('Error checking admin role:', roleError);
      return withCors(
        req,
        new Response(
          JSON.stringify({ isAdmin: false, error: 'Error checking role' }),
          { status: 500, headers: { 'Content-Type': 'application/json' } }
        )
      );
    }

    return withCors(
      req,
      new Response(
        JSON.stringify({ isAdmin: isAdmin || false, userId: user.id }),
        { headers: { 'Content-Type': 'application/json' } }
      )
    );
  } catch (error) {
    console.error('Error in check-admin function:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return withCors(
      req,
      new Response(
        JSON.stringify({ isAdmin: false, error: errorMessage }),
        { status: 500, headers: { 'Content-Type': 'application/json' } }
      )
    );
  }
});
