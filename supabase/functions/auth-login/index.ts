import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.78.0';
import { createRateLimiter } from '../_shared/security/rateLimiter.ts';
import { getClientIp } from '../_shared/util/ip.ts';
import { normalizeIdentifier } from '../_shared/util/normalize.ts';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Credentials': 'true',
};

/**
 * Handle login request with rate limiting and secure session management
 * Implements per-IP and per-identifier throttling with exponential backoff
 */
export async function handleLogin(req: Request): Promise<Response> {
  const supabaseClient = createClient(
    Deno.env.get('SUPABASE_URL') ?? '',
    Deno.env.get('SUPABASE_ANON_KEY') ?? '',
  );

  const rateLimiter = createRateLimiter(supabaseClient);

  try {
    const { email, password } = await req.json();

    if (!email || !password) {
      return new Response(
        JSON.stringify({ error: 'Email and password are required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Extract client IP and normalize identifier
    const ip = getClientIp(req);
    const identifierKey = await normalizeIdentifier(email);

    // Check rate limits before attempting authentication
    const verdict = await rateLimiter.checkAndConsume(ip, identifierKey);
    if (!verdict.allowed) {
      console.log('Login blocked by rate limiter', {
        ip,
        idPrefix: identifierKey.slice(0, 8),
        reason: verdict.reason,
      });

      return new Response(
        JSON.stringify({ error: 'Too many attempts. Please try again later.' }),
        {
          status: 429,
          headers: {
            ...corsHeaders,
            'Content-Type': 'application/json',
            'Retry-After': String(verdict.retryAfterSeconds || 60),
          },
        }
      );
    }

    // Attempt authentication
    const { data, error } = await supabaseClient.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      // Record failure for rate limiting
      await rateLimiter.recordFailure(ip, identifierKey);

      console.log('Login failed', {
        ip,
        idPrefix: identifierKey.slice(0, 8),
      });

      // Return generic error message to prevent enumeration
      return new Response(
        JSON.stringify({ error: 'Invalid email or password' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    if (!data.session) {
      await rateLimiter.recordFailure(ip, identifierKey);
      return new Response(
        JSON.stringify({ error: 'Invalid email or password' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Record successful login - reset rate limit counters
    await rateLimiter.recordSuccess(identifierKey);

    // Set HttpOnly cookie with the session
    // Security: HttpOnly prevents JavaScript access, Secure ensures HTTPS-only, SameSite prevents CSRF
    const cookieHeader = `sb-session=${encodeURIComponent(JSON.stringify({
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_at: data.session.expires_at,
    }))}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800`; // 7 days

    console.log('Login successful', {
      userId: data.user.id,
      ip,
      idPrefix: identifierKey.slice(0, 8),
    });

    return new Response(
      JSON.stringify({ 
        user: {
          id: data.user.id,
          email: data.user.email,
        },
        success: true 
      }),
      {
        status: 200,
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
          'Set-Cookie': cookieHeader,
        },
      }
    );
  } catch (error) {
    console.error('Unexpected error:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  return handleLogin(req);
});
