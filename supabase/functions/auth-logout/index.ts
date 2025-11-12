import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.78.0';

/**
 * SECURITY: Parse allowed origins from environment variable
 * Uses fail-closed approach - no origins allowed if not configured
 */
function parseAllowedOrigins(): Set<string> {
  const originsEnv = Deno.env.get('LOGOUT_ALLOWED_ORIGINS');
  if (!originsEnv) {
    console.warn('SECURITY: LOGOUT_ALLOWED_ORIGINS not configured, no cross-origin requests allowed');
    return new Set<string>();
  }
  
  const origins = originsEnv
    .split(',')
    .map(o => o.trim())
    .filter(o => o.length > 0);
  
  console.log('CORS: Allowed origins configured', { count: origins.length });
  return new Set(origins);
}

/**
 * SECURITY: Validate if origin is in the allowlist
 */
function isOriginAllowed(origin: string | null, allowed: Set<string>): boolean {
  if (!origin) return false;
  return allowed.has(origin);
}

/**
 * SECURITY: Validate requested headers are subset of allowed minimal set
 * Only allows content-type for logout endpoint (no privileged headers)
 */
function areRequestedHeadersAllowed(
  requested: string | null,
  allowedHeaders: string[]
): boolean {
  if (!requested) return true; // No headers requested is fine
  
  const requestedList = requested
    .toLowerCase()
    .split(',')
    .map(h => h.trim())
    .filter(h => h.length > 0);
  
  const allowedSet = new Set(allowedHeaders.map(h => h.toLowerCase()));
  
  // Every requested header must be in allowed set
  for (const header of requestedList) {
    if (!allowedSet.has(header)) {
      console.warn('SECURITY: Blocked preflight with unauthorized header', { 
        requested: header,
        allowed: allowedHeaders 
      });
      return false;
    }
  }
  
  return true;
}

/**
 * SECURITY: Build CORS headers for allowed origin (never wildcard)
 * Includes Vary headers to prevent cache confusion
 */
function buildCorsHeaders(
  origin: string,
  options: {
    allowCredentials?: boolean;
    allowedHeaders: string[];
    allowedMethods: string[];
    isPreflight?: boolean;
  }
): Record<string, string> {
  const headers: Record<string, string> = {
    // SECURITY: Specific origin only, never wildcard
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': options.allowedMethods.join(', '),
    'Access-Control-Allow-Headers': options.allowedHeaders.join(', '),
    // SECURITY: Prevent cache confusion by varying on Origin
    'Vary': 'Origin, Access-Control-Request-Headers, Access-Control-Request-Method',
  };
  
  // SECURITY: Only set credentials for specific allowed origin when needed
  // Never set with wildcard (already prevented above)
  if (options.allowCredentials) {
    headers['Access-Control-Allow-Credentials'] = 'true';
  }
  
  // Cache preflight for 24 hours to reduce overhead
  if (options.isPreflight) {
    headers['Access-Control-Max-Age'] = '86400';
  }
  
  return headers;
}

/**
 * Main request handler with secure CORS validation
 */
export async function handleRequest(req: Request): Promise<Response> {
  const allowedOrigins = parseAllowedOrigins();
  const origin = req.headers.get('Origin');
  
  // SECURITY: Handle preflight with strict validation
  if (req.method === 'OPTIONS') {
    // Validate origin is allowed
    if (!isOriginAllowed(origin, allowedOrigins)) {
      console.warn('SECURITY: Blocked preflight from disallowed origin', { origin });
      return new Response('Forbidden', { 
        status: 403,
        headers: { 'Content-Type': 'text/plain' }
      });
    }
    
    // Validate requested method
    const requestedMethod = req.headers.get('Access-Control-Request-Method');
    if (requestedMethod !== 'POST') {
      console.warn('SECURITY: Blocked preflight with invalid method', { 
        method: requestedMethod 
      });
      return new Response('Forbidden', { 
        status: 403,
        headers: { 'Content-Type': 'text/plain' }
      });
    }
    
    // SECURITY: Allow minimal headers for logout (content-type, CSRF token, requested-with)
    const requestedHeaders = req.headers.get('Access-Control-Request-Headers');
    const allowedHeaders = ['content-type', 'x-csrf-token', 'x-requested-with'];
    
    if (!areRequestedHeadersAllowed(requestedHeaders, allowedHeaders)) {
      return new Response('Forbidden', { 
        status: 403,
        headers: { 'Content-Type': 'text/plain' }
      });
    }
    
    // Return successful preflight response
    const corsHeaders = buildCorsHeaders(origin!, {
      allowCredentials: true, // Logout uses HttpOnly cookies
      allowedHeaders,
      allowedMethods: ['POST'],
      isPreflight: true,
    });
    
    return new Response(null, {
      status: 204,
      headers: corsHeaders,
    });
  }

  // SECURITY: Enforce POST-only for logout (prevent CSRF via GET)
  if (req.method !== 'POST') {
    console.warn('SECURITY: Blocked non-POST request to logout', { method: req.method });
    return new Response(
      JSON.stringify({ error: 'Method not allowed' }),
      { 
        status: 405,
        headers: { 
          'Content-Type': 'application/json',
          'Allow': 'POST'
        }
      }
    );
  }

  // SECURITY: Strict origin/referrer enforcement for POST (mandatory)
  let derivedOrigin = origin;
  
  // If no Origin header, try to derive from Referer (for non-CORS requests)
  if (!derivedOrigin) {
    const referer = req.headers.get('referer');
    if (referer) {
      try {
        derivedOrigin = new URL(referer).origin;
      } catch (e) {
        console.warn('SECURITY: Malformed Referer header', { referer });
        return new Response(
          JSON.stringify({ error: 'Forbidden' }),
          { 
            status: 403,
            headers: { 'Content-Type': 'application/json' }
          }
        );
      }
    }
  }
  
  // SECURITY: Reject if no origin/referer or if not in allowlist
  if (!derivedOrigin || !isOriginAllowed(derivedOrigin, allowedOrigins)) {
    console.warn('SECURITY: Blocked POST from disallowed or missing origin', { 
      origin: derivedOrigin || 'none' 
    });
    return new Response(
      JSON.stringify({ error: 'Forbidden' }),
      { 
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }

  // Build CORS headers for response (only if origin is allowed)
  const responseCorsHeaders = origin && isOriginAllowed(origin, allowedOrigins)
    ? buildCorsHeaders(origin, {
        allowCredentials: true, // Logout uses HttpOnly cookies and CSRF tokens
        allowedHeaders: ['content-type', 'x-csrf-token', 'x-requested-with'],
        allowedMethods: ['POST'],
      })
    : {};

  // SECURITY: CSRF protection - double-submit cookie pattern
  // Extract CSRF token from cookie
  const cookieHeader = req.headers.get('cookie') || '';
  const csrfCookieMatch = cookieHeader.match(/(?:^|; )sb-csrf=([^;]+)/);
  const csrfCookie = csrfCookieMatch ? csrfCookieMatch[1] : null;
  
  // Extract CSRF token from header
  const csrfHeader = req.headers.get('X-CSRF-Token');
  
  // SECURITY: Require matching CSRF tokens
  if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
    console.warn('SECURITY: CSRF token validation failed', { 
      hasCookie: !!csrfCookie,
      hasHeader: !!csrfHeader,
      match: csrfCookie === csrfHeader
    });
    return new Response(
      JSON.stringify({ error: 'Forbidden' }),
      { 
        status: 403,
        headers: { 
          ...responseCorsHeaders,
          'Content-Type': 'application/json' 
        }
      }
    );
  }

  try {
    // Extract session token from cookie to invalidate it server-side
    // Note: cookieHeader already extracted above for CSRF validation
    const sessionMatch = cookieHeader.match(/sb-session=([^;]+)/);
    
    if (sessionMatch) {
      try {
        const sessionData = JSON.parse(decodeURIComponent(sessionMatch[1]));
        
        // Create Supabase client with the user's access token
        const supabaseClient = createClient(
          Deno.env.get('SUPABASE_URL') ?? '',
          Deno.env.get('SUPABASE_ANON_KEY') ?? '',
          {
            global: {
              headers: {
                Authorization: `Bearer ${sessionData.access_token}`,
              },
            },
          }
        );

        // Invalidate the session server-side in Supabase Auth
        // This revokes the access and refresh tokens
        const { error } = await supabaseClient.auth.signOut();
        
        if (error) {
          console.error('Supabase signOut error:', error);
          // Continue with cookie clearing even if signOut fails
        } else {
          console.log('Session invalidated server-side');
        }
      } catch (parseError) {
        console.error('Error parsing session cookie:', parseError);
        // Continue with cookie clearing even if parsing fails
      }
    }

    // Clear the HttpOnly session cookie and CSRF token
    // Security: Setting Max-Age=0 immediately expires the cookies
    const clearSessionCookie = 'sb-session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0';
    const clearCsrfCookie = 'sb-csrf=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0';

    console.log('Logout successful - session cookie cleared');

    return new Response(
      JSON.stringify({ success: true }),
      {
        status: 200,
        headers: {
          ...responseCorsHeaders,
          'Content-Type': 'application/json',
          'Set-Cookie': [clearSessionCookie, clearCsrfCookie].join(', '),
        },
      }
    );
  } catch (error) {
    console.error('Logout error:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      { 
        status: 500, 
        headers: { 
          ...responseCorsHeaders, 
          'Content-Type': 'application/json' 
        } 
      }
    );
  }
}

// Start the server
Deno.serve(handleRequest);
