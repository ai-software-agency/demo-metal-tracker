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
 * SECURITY: Validate Authorization header format and content
 * 
 * Ensures:
 * - Bearer scheme present
 * - Token contains only valid JWT characters (A-Za-z0-9-_.)
 * - No control characters (CR/LF/TAB) that could enable header injection
 * - Reasonable length bounds (20-4096 chars)
 * 
 * @returns { valid: boolean, token?: string, error?: string }
 */
function validateAuthorizationHeader(authHeader: string | null): {
  valid: boolean;
  token?: string;
  error?: string;
} {
  if (!authHeader) {
    return { valid: false, error: 'Authorization header required' };
  }
  
  // Must start with "Bearer " (case-insensitive)
  if (!authHeader.toLowerCase().startsWith('bearer ')) {
    return { valid: false, error: 'Authorization must use Bearer scheme' };
  }
  
  // Extract token part
  const token = authHeader.slice(7).trim();
  
  // SECURITY: Reject any control characters (CR, LF, TAB, etc.) to prevent header injection
  // Check for ASCII control characters (< 0x20) and CR/LF specifically
  if (/[\r\n\t\f\v\0-\x1F]/.test(authHeader)) {
    console.warn('SECURITY: Blocked Authorization with control characters');
    return { valid: false, error: 'Invalid Authorization header format' };
  }
  
  // Length validation: JWT tokens are typically 100-2000 chars
  // Allow 20-4096 to be permissive but prevent abuse
  if (token.length < 20 || token.length > 4096) {
    return { valid: false, error: 'Invalid token length' };
  }
  
  // SECURITY: JWT tokens should only contain base64url characters and dots
  // Pattern: header.payload.signature where each part is [A-Za-z0-9_-]+
  if (!/^[A-Za-z0-9_\-\.]+$/.test(token)) {
    console.warn('SECURITY: Blocked Authorization with invalid characters');
    return { valid: false, error: 'Invalid token format' };
  }
  
  // Ensure proper JWT structure (three parts separated by dots)
  const parts = token.split('.');
  if (parts.length !== 3) {
    return { valid: false, error: 'Invalid JWT structure' };
  }
  
  return { valid: true, token };
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
    
    // SECURITY: Allow minimal headers for logout (authorization, content-type)
    const requestedHeaders = req.headers.get('Access-Control-Request-Headers');
    const allowedHeaders = ['authorization', 'content-type', 'x-csrf-token', 'x-requested-with'];
    
    if (!areRequestedHeadersAllowed(requestedHeaders, allowedHeaders)) {
      return new Response('Forbidden', { 
        status: 403,
        headers: { 'Content-Type': 'text/plain' }
      });
    }
    
    // Return successful preflight response
    const corsHeaders = buildCorsHeaders(origin!, {
      allowCredentials: false, // No longer using cookies for authentication
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
        allowCredentials: false, // No longer using cookies for authentication
        allowedHeaders: ['authorization', 'content-type', 'x-csrf-token', 'x-requested-with'],
        allowedMethods: ['POST'],
      })
    : {};

  // SECURITY: Validate Authorization header (required for authenticated logout)
  // DO NOT source Authorization from cookies - this prevents header injection attacks
  // where an attacker could use this endpoint as a proxy to revoke arbitrary tokens
  const authHeader = req.headers.get('Authorization');
  const authValidation = validateAuthorizationHeader(authHeader);
  
  if (!authValidation.valid) {
    console.warn('SECURITY: Invalid or missing Authorization header', {
      error: authValidation.error,
      hasHeader: !!authHeader,
    });
    return new Response(
      JSON.stringify({ 
        error: 'Unauthorized',
        message: authValidation.error 
      }),
      { 
        status: 401,
        headers: { 
          ...responseCorsHeaders,
          'Content-Type': 'application/json' 
        }
      }
    );
  }

  try {
    // SECURITY: Create Supabase client with validated Bearer token
    // This binds the logout to the authenticated user's own session only
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      {
        global: {
          headers: {
            // Use the sanitized, validated Authorization header
            Authorization: `Bearer ${authValidation.token}`,
          },
        },
      }
    );
    
    // SECURITY: Authenticate the caller before allowing signOut
    // This ensures we only revoke the caller's own token, not an arbitrary value
    const { data: userData, error: userError } = await supabaseClient.auth.getUser();
    
    if (userError || !userData?.user) {
      console.warn('SECURITY: Logout attempted with invalid token', {
        error: userError?.message,
        hasUser: !!userData?.user,
      });
      return new Response(
        JSON.stringify({ 
          error: 'Unauthorized',
          message: 'Invalid or expired token' 
        }),
        { 
          status: 401,
          headers: { 
            ...responseCorsHeaders,
            'Content-Type': 'application/json' 
          }
        }
      );
    }

    // SECURITY: Only revoke the authenticated user's own session
    // This prevents the endpoint from being used as a token revocation proxy
    const { error: signOutError } = await supabaseClient.auth.signOut();
    
    if (signOutError) {
      console.error('Supabase signOut error:', {
        userId: userData.user.id,
        error: signOutError.message,
      });
      // Return error but don't expose internal details
      return new Response(
        JSON.stringify({ error: 'Logout failed' }),
        { 
          status: 500,
          headers: { 
            ...responseCorsHeaders,
            'Content-Type': 'application/json' 
          }
        }
      );
    }

    console.log('Session invalidated server-side', {
      userId: userData.user.id,
      email: userData.user.email,
    });

    // SECURITY: Clear auth cookies using separate Set-Cookie headers
    // Do not concatenate with commas - use headers.append for multiple cookies
    const responseHeaders = new Headers({
      ...responseCorsHeaders,
      'Content-Type': 'application/json',
    });
    
    // Clear session cookie with secure attributes
    responseHeaders.append(
      'Set-Cookie',
      'sb-session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
    );
    
    // Clear CSRF cookie with secure attributes
    responseHeaders.append(
      'Set-Cookie',
      'sb-csrf=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
    );
    
    // Clear any other auth-related cookies your app might use
    responseHeaders.append(
      'Set-Cookie',
      'sb-access-token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
    );
    responseHeaders.append(
      'Set-Cookie',
      'sb-refresh-token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
    );

    console.log('Logout successful - session revoked and cookies cleared');

    return new Response(
      JSON.stringify({ 
        success: true,
        message: 'Logged out successfully' 
      }),
      {
        status: 200,
        headers: responseHeaders,
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
