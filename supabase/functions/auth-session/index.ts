import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.78.0';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Credentials': 'true',
};

/**
 * Parse JWT payload without verification (signature already verified by getUser)
 * Returns claims object or null if parsing fails
 */
function parseJwtClaims(token: string): any {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    // Base64url decode the payload (middle segment)
    const payload = parts[1];
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = atob(base64);
    return JSON.parse(jsonPayload);
  } catch (error) {
    console.error('Failed to parse JWT claims:', error);
    return null;
  }
}

/**
 * Check if session has verified MFA based on JWT claims
 * Checks for strong authentication methods in amr array or AAL level >= 2
 */
function isMfaVerified(claims: any, minAal: number = 2): boolean {
  if (!claims) return false;
  
  // Check amr (Authentication Methods References) array for strong factors
  const amr = Array.isArray(claims?.amr) 
    ? claims.amr.map((m: any) => String(m).toLowerCase()) 
    : [];
  const strongMethods = ['otp', 'totp', 'webauthn', 'sms', 'mfa'];
  const hasStrongAmr = amr.some((m: string) => strongMethods.includes(m));
  
  // Check aal (Authenticator Assurance Level)
  const aalRaw = claims?.aal;
  let aalNum = 1;
  if (typeof aalRaw === 'number') {
    aalNum = aalRaw;
  } else if (typeof aalRaw === 'string') {
    const match = aalRaw.match(/\d+/);
    aalNum = match ? Number(match[0]) : 1;
  }
  
  return hasStrongAmr || aalNum >= minAal;
}

/**
 * Read environment variable as boolean, with default fallback
 */
function readEnvBoolean(key: string, defaultValue: boolean): boolean {
  const val = Deno.env.get(key);
  if (val === undefined) return defaultValue;
  return val.toLowerCase() === 'true' || val === '1';
}

/**
 * Read environment variable as number, with default fallback
 */
function readEnvNumber(key: string, defaultValue: number): number {
  const val = Deno.env.get(key);
  if (val === undefined) return defaultValue;
  const num = Number(val);
  return isNaN(num) ? defaultValue : num;
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Security: Require Authorization header with valid JWT
    const authHeader = req.headers.get('Authorization') || '';
    if (!authHeader.startsWith('Bearer ')) {
      return new Response(
        JSON.stringify({ error: 'Unauthorized' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Create Supabase client with the Authorization header
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      {
        global: { headers: { Authorization: authHeader } },
      }
    );

    // Verify the user is authenticated via JWT
    const { data: { user }, error } = await supabaseClient.auth.getUser();

    if (error || !user) {
      return new Response(
        JSON.stringify({ error: 'Unauthorized' }),
        {
          status: 401,
          headers: {
            ...corsHeaders,
            'Content-Type': 'application/json',
          },
        }
      );
    }

    // Check if user is admin using has_role function
    const { data: hasAdminRole, error: roleError } = await supabaseClient.rpc('has_role', {
      _user_id: user.id,
      _role: 'admin',
    });

    if (roleError) {
      console.error('Role check error:', roleError);
    }

    // MFA enforcement for admin accounts
    const requireMfa = readEnvBoolean('ADMIN_MFA_REQUIRED', true);
    const minAal = readEnvNumber('ADMIN_MIN_AAL', 2);
    
    let isAdmin = false;
    let mfaRequired = false;
    let adminEligible = false;

    if (hasAdminRole) {
      // Parse JWT claims to check MFA status
      const token = authHeader.replace('Bearer ', '');
      const claims = parseJwtClaims(token);
      const mfaVerified = isMfaVerified(claims, minAal);
      
      if (requireMfa && !mfaVerified) {
        // Admin role present but MFA not verified - require step-up authentication
        console.warn(`Admin access attempt without MFA: user_id=${user.id}, email=${user.email}`);
        mfaRequired = true;
        adminEligible = true;
        isAdmin = false;
        
        return new Response(
          JSON.stringify({
            authenticated: true,
            user: {
              id: user.id,
              email: user.email,
            },
            isAdmin: false,
            mfaRequired: true,
            adminEligible: true,
          }),
          {
            status: 401,
            headers: {
              ...corsHeaders,
              'Content-Type': 'application/json',
              'WWW-Authenticate': 'MFA realm="admin", error="mfa_required"',
            },
          }
        );
      }
      
      // MFA verified or not required - grant admin access
      isAdmin = true;
    }

    return new Response(
      JSON.stringify({
        authenticated: true,
        user: {
          id: user.id,
          email: user.email,
        },
        isAdmin,
      }),
      {
        status: 200,
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
        },
      }
    );
  } catch (error) {
    console.error('Session check error:', error);
    return new Response(
      JSON.stringify({ authenticated: false, user: null }),
      { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
