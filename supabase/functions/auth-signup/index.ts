import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.78.0';
import { createRateLimiter } from '../_shared/security/rateLimiter.ts';
import { normalizeIdentifier } from '../_shared/util/normalize.ts';
import { getClientIp } from '../_shared/util/ip.ts';
import { preflight, withCors } from '../_shared/util/cors.ts';
import { normalizePassword, validatePassword } from '../_shared/passwordPolicy.ts';

/**
 * Sleep utility for timing attack mitigation
 * Adds artificial delay to prevent timing-based user enumeration
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Validate email format using basic RFC-compliant regex
 */
function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Main signup handler with security controls:
 * - Rate limiting per IP and per email
 * - Enumeration prevention via normalized responses
 * - CORS restrictions to allowed origins
 * - Input validation for email and password
 */
export async function handleSignup(req: Request): Promise<Response> {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return preflight(req);
  }

  const commonHeaders = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
  };

  try {
    // Parse and validate request body size (max ~10KB)
    const contentLength = req.headers.get('content-length');
    if (contentLength && parseInt(contentLength) > 10240) {
      return withCors(req, new Response(
        JSON.stringify({ success: false, message: 'Request body too large.' }),
        { status: 400, headers: commonHeaders }
      ));
    }

    let body;
    try {
      body = await req.json();
    } catch {
      return withCors(req, new Response(
        JSON.stringify({ success: false, message: 'Invalid request format.' }),
        { status: 400, headers: commonHeaders }
      ));
    }

    const { email, password } = body;

    // Input validation - use generic messages to avoid enumeration
    if (!email || !password) {
      return withCors(req, new Response(
        JSON.stringify({ success: false, message: 'Invalid signup request.' }),
        { status: 400, headers: commonHeaders }
      ));
    }

    if (typeof email !== 'string' || typeof password !== 'string') {
      return withCors(req, new Response(
        JSON.stringify({ success: false, message: 'Invalid signup request.' }),
        { status: 400, headers: commonHeaders }
      ));
    }

    // Validate email format
    if (!isValidEmail(email)) {
      return withCors(req, new Response(
        JSON.stringify({ success: false, message: 'Invalid signup request.' }),
        { status: 400, headers: commonHeaders }
      ));
    }

    // Normalize and validate password against security policy
    const normalizedPassword = normalizePassword(password);
    const passwordValidation = validatePassword(normalizedPassword);
    
    if (!passwordValidation.ok) {
      return withCors(req, new Response(
        JSON.stringify({ 
          success: false, 
          message: passwordValidation.message || 'Password does not meet security requirements.',
          codes: passwordValidation.codes || []
        }),
        { status: 400, headers: commonHeaders }
      ));
    }

    // Extract client IP for rate limiting
    const clientIp = getClientIp(req);
    
    // Normalize email (lowercase, trim)
    const normalizedEmail = email.trim().toLowerCase();
    const emailHash = await normalizeIdentifier(normalizedEmail);

    // Initialize rate limiter
    const rateLimiter = createRateLimiter();

    // Apply rate limiting: per-IP and per-email
    // This prevents mass account creation and email bombing
    const rateLimitResult = await rateLimiter.checkAndConsume(clientIp, emailHash);
    
    if (!rateLimitResult.allowed) {
      console.log('Rate limit exceeded for signup:', { ip: clientIp, reason: rateLimitResult.reason });
      
      const retryHeaders = {
        ...commonHeaders,
        ...(rateLimitResult.retryAfterSeconds ? { 'Retry-After': rateLimitResult.retryAfterSeconds.toString() } : {}),
      };
      
      return withCors(req, new Response(
        JSON.stringify({ 
          success: false, 
          message: 'Too many requests. Please try again later.' 
        }),
        { status: 429, headers: retryHeaders }
      ));
    }

    // Create Supabase client
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
    );

    // Attempt signup with normalized password
    const { data, error } = await supabaseClient.auth.signUp({
      email: normalizedEmail,
      password: normalizedPassword,
    });

    // Security: Record success to reset failure counters
    if (!error) {
      await rateLimiter.recordSuccess(emailHash);
      console.log('Signup successful for user:', data.user?.id);
    } else {
      // Log error for monitoring but don't expose details to client
      console.error('Signup error:', { 
        message: error.message, 
        name: error.name, 
        status: error.status 
      });
    }

    // SECURITY: Add artificial delay to prevent timing-based enumeration
    // Randomized jitter (80-120ms) makes it harder to distinguish success vs. failure
    // based on response time alone
    const jitterMs = 80 + Math.floor(Math.random() * 40);
    await sleep(jitterMs);

    // CRITICAL: Normalize response to prevent user enumeration
    // Always return 202 with generic message regardless of success/failure
    // This prevents attackers from determining if an email is already registered
    return withCors(req, new Response(
      JSON.stringify({ 
        success: true,
        message: 'If the email is eligible, you will receive a message with next steps.',
      }),
      {
        status: 202,
        headers: commonHeaders,
      }
    ));

  } catch (error) {
    console.error('Unexpected signup error:', error);
    
    // Generic error response - don't leak internal details
    return withCors(req, new Response(
      JSON.stringify({ success: false, message: 'An error occurred. Please try again later.' }),
      { status: 500, headers: commonHeaders }
    ));
  }
}

// Start the server
Deno.serve(handleSignup);
