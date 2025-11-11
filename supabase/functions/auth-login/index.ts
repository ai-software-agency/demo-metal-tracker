import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.78.0';
import { createRateLimiter } from '../_shared/security/rateLimiter.ts';
import { RateLimitBackendUnavailable } from '../_shared/security/attemptStore.ts';
import { getClientIp } from '../_shared/util/ip.ts';
import { normalizeIdentifier } from '../_shared/util/normalize.ts';
import { preflight, withCors } from '../_shared/util/cors.ts';

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
      return withCors(
        req,
        new Response(
          JSON.stringify({ error: 'Email and password are required' }),
          { status: 400, headers: { 'Content-Type': 'application/json' } }
        )
      );
    }

    // Extract client IP and normalize identifier
    const ip = getClientIp(req);
    const identifierKey = await normalizeIdentifier(email);

    // SECURITY: Check rate limits before attempting authentication
    // CRITICAL: This happens BEFORE password verification to prevent brute force
    let verdict;
    try {
      verdict = await rateLimiter.checkAndConsume(ip, identifierKey);
    } catch (error) {
      // FAIL CLOSED: If rate limit storage fails, block the request
      if (error instanceof RateLimitBackendUnavailable) {
        console.error('SECURITY: Rate limit backend unavailable, blocking login attempt', {
          ip,
          idPrefix: identifierKey.slice(0, 8),
          operation: error.operation,
        });
        
        const response = new Response(
          JSON.stringify({ 
            error: 'Service temporarily unavailable. Please try again later.' 
          }),
          {
            status: 503,
            headers: {
              'Content-Type': 'application/json',
              'Retry-After': '60',
            },
          }
        );
        return withCors(req, response);
      }
      // Re-throw unexpected errors
      throw error;
    }

    if (!verdict.allowed) {
      console.log('Login blocked by rate limiter', {
        ip,
        idPrefix: identifierKey.slice(0, 8),
        reason: verdict.reason,
      });

      const response = new Response(
        JSON.stringify({ error: 'Too many attempts. Please try again later.' }),
        {
          status: 429,
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': String(verdict.retryAfterSeconds || 60),
          },
        }
      );
      return withCors(req, response);
    }

    // Attempt authentication
    const { data, error } = await supabaseClient.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      // Record failure for rate limiting
      try {
        await rateLimiter.recordFailure(ip, identifierKey);
      } catch (storageError) {
        // Log but don't block response if failure recording fails
        console.error('SECURITY: Failed to record login failure', {
          ip,
          idPrefix: identifierKey.slice(0, 8),
          error: storageError instanceof Error ? storageError.message : 'unknown',
        });
      }

      console.log('Login failed', {
        ip,
        idPrefix: identifierKey.slice(0, 8),
      });

      // Return generic error message to prevent enumeration
      return withCors(
        req,
        new Response(
          JSON.stringify({ error: 'Invalid email or password' }),
          { status: 401, headers: { 'Content-Type': 'application/json' } }
        )
      );
    }

    if (!data.session) {
      try {
        await rateLimiter.recordFailure(ip, identifierKey);
      } catch (storageError) {
        console.error('SECURITY: Failed to record login failure', {
          ip,
          idPrefix: identifierKey.slice(0, 8),
          error: storageError instanceof Error ? storageError.message : 'unknown',
        });
      }
      
      return withCors(
        req,
        new Response(
          JSON.stringify({ error: 'Invalid email or password' }),
          { status: 401, headers: { 'Content-Type': 'application/json' } }
        )
      );
    }

    // Record successful login - reset rate limit counters
    try {
      await rateLimiter.recordSuccess(identifierKey);
    } catch (storageError) {
      // Log but don't block successful login if reset fails
      console.error('SECURITY: Failed to reset rate limit counters on success', {
        userId: data.user.id,
        idPrefix: identifierKey.slice(0, 8),
        error: storageError instanceof Error ? storageError.message : 'unknown',
      });
    }

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

    return withCors(
      req,
      new Response(
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
            'Content-Type': 'application/json',
            'Set-Cookie': cookieHeader,
          },
        }
      )
    );
  } catch (error) {
    console.error('Unexpected error:', error);
    return withCors(
      req,
      new Response(
        JSON.stringify({ error: 'Internal server error' }),
        { status: 500, headers: { 'Content-Type': 'application/json' } }
      )
    );
  }
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return preflight(req);
  }

  return handleLogin(req);
});
