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
    
    // SECURITY: Only allow content-type header (no authorization, apikey, etc.)
    const requestedHeaders = req.headers.get('Access-Control-Request-Headers');
    const allowedHeaders = ['content-type'];
    
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

  // SECURITY: Validate origin for actual requests (if Origin header present)
  if (origin && !isOriginAllowed(origin, allowedOrigins)) {
    console.warn('SECURITY: Blocked POST from disallowed origin', { origin });
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
        allowCredentials: true, // Logout uses HttpOnly cookies
        allowedHeaders: ['content-type'],
        allowedMethods: ['POST'],
      })
    : {};

  try {
    // Extract session token from cookie to invalidate it server-side
    const cookieHeader = req.headers.get('cookie') || '';
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

    // Clear the HttpOnly session cookie
    // Security: Setting Max-Age=0 immediately expires the cookie
    const clearCookieHeader = 'sb-session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0';

    console.log('Logout successful - session cookie cleared');

    return new Response(
      JSON.stringify({ success: true }),
      {
        status: 200,
        headers: {
          ...responseCorsHeaders,
          'Content-Type': 'application/json',
          'Set-Cookie': clearCookieHeader,
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
