/**
 * CORS Security Helper
 * 
 * Implements strict CORS controls based on an allowlist from environment variables.
 * Prevents unauthorized cross-origin access to sensitive endpoints.
 * 
 * SECURITY: Never uses wildcard (*) origins with credentials to prevent CORS misconfigurations.
 * 
 * Environment Variables:
 * - ALLOWED_ORIGINS: Comma-separated list of allowed origins (e.g., "https://example.com,https://app.example.com")
 *                    If not set, defaults to local development origins for safety
 * - ALLOW_CREDENTIALS: Set to 'true' to enable credentials (default: true for authenticated endpoints)
 */

interface CorsConfig {
  allowedOrigins: Set<string>;
  allowedMethods: string[];
  allowedHeaders: string[];
  allowCredentials: boolean;
}

/**
 * Load CORS configuration from environment
 * @param defaultMethods - Default allowed methods for this endpoint
 * @param defaultHeaders - Default allowed headers for this endpoint
 */
function getConfig(
  defaultMethods: string[] = ['GET', 'POST', 'OPTIONS'],
  defaultHeaders: string[] = ['content-type', 'authorization', 'x-client-info', 'apikey']
): CorsConfig {
  const originsEnv = Deno.env.get('ALLOWED_ORIGINS');
  
  // Default to local development origins if not configured
  // SECURITY: NEVER default to '*' for safety
  const defaultOrigins = [
    'http://localhost:8080',
    'http://localhost:5173',
    'http://127.0.0.1:8080',
    'http://127.0.0.1:5173',
  ];
  
  const originsList = originsEnv
    ? originsEnv.split(',').map(o => o.trim()).filter(o => o.length > 0)
    : defaultOrigins;
  
  // Use Set for O(1) lookup performance
  const allowedOrigins = new Set(originsList);
  
  // Read ALLOW_CREDENTIALS (default true for authenticated endpoints)
  const credentialsEnv = Deno.env.get('ALLOW_CREDENTIALS');
  const allowCredentials = credentialsEnv === undefined || credentialsEnv === 'true';
  
  return {
    allowedOrigins,
    allowedMethods: defaultMethods,
    allowedHeaders: defaultHeaders,
    allowCredentials,
  };
}

/**
 * Check if origin is allowed based on allowlist
 * @param req - The incoming request
 * @param config - CORS configuration (optional, will load from env if not provided)
 * @returns The origin if allowed, null otherwise
 */
export function getAllowedOrigin(
  req: Request,
  config?: CorsConfig
): string | null {
  const origin = req.headers.get('origin');
  
  // No Origin header means same-origin request (not a CORS request)
  // Return null to indicate CORS headers are not needed
  if (!origin) {
    return null;
  }
  
  const corsConfig = config || getConfig();
  
  // SECURITY: Only allow explicitly whitelisted origins
  if (corsConfig.allowedOrigins.has(origin)) {
    return origin;
  }
  
  return null;
}

/**
 * Check if request has credentials (cookies or authorization header)
 * Used to detect potentially dangerous cross-origin credentialed requests
 */
function hasCredentials(req: Request): boolean {
  return !!(req.headers.get('cookie') || req.headers.get('authorization'));
}

/**
 * Handle CORS preflight OPTIONS request with strict origin validation
 * 
 * SECURITY: 
 * - Returns 403 for disallowed origins (no ACAO header)
 * - Returns 204 with strict CORS headers for allowed origins
 * - Reflects Access-Control-Request-Headers or uses default list
 * - Includes Vary: Origin for proper caching
 * 
 * @param req - The preflight request
 * @param allowedMethods - Methods to allow (defaults to GET, POST, OPTIONS)
 * @returns Response with appropriate CORS headers or 403
 */
export function preflight(
  req: Request,
  allowedMethods: string[] = ['GET', 'POST', 'OPTIONS']
): Response {
  const config = getConfig(allowedMethods);
  const origin = getAllowedOrigin(req, config);
  
  // SECURITY: Reject preflight from disallowed origins
  if (!origin) {
    console.warn('CORS preflight rejected: disallowed origin', {
      origin: req.headers.get('origin') || 'none',
      method: req.headers.get('access-control-request-method'),
    });
    
    return new Response(
      JSON.stringify({ error: 'Forbidden: Origin not allowed' }),
      { 
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
  
  // Reflect requested headers or use default allowlist
  const requestedHeaders = req.headers.get('access-control-request-headers');
  const allowedHeaders = requestedHeaders
    ? requestedHeaders.split(',').map(h => h.trim()).join(', ')
    : config.allowedHeaders.join(', ');
  
  const headers: Record<string, string> = {
    // SECURITY: Echo exact origin, never use wildcard with credentials
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': config.allowedMethods.join(', '),
    'Access-Control-Allow-Headers': allowedHeaders,
    'Access-Control-Max-Age': '86400', // 24 hours
    // SECURITY: Vary header ensures proper caching per origin
    'Vary': 'Origin',
  };

  // SECURITY: Only include credentials header if explicitly enabled
  if (config.allowCredentials) {
    headers['Access-Control-Allow-Credentials'] = 'true';
  }

  return new Response(null, {
    status: 204,
    headers,
  });
}

/**
 * Apply CORS headers to a response with strict origin validation
 * 
 * SECURITY:
 * - Only sets CORS headers for explicitly allowed origins
 * - Rejects credentialed requests from disallowed origins with 403
 * - Never uses wildcard (*) origins
 * - Includes Vary: Origin for proper caching
 * - Only includes Access-Control-Allow-Credentials when explicitly enabled
 * 
 * @param req - The incoming request
 * @param response - The response to wrap with CORS headers
 * @returns Response with CORS headers if origin is allowed, or 403 if disallowed with credentials
 */
export function withCors(req: Request, response: Response): Response {
  const config = getConfig();
  const origin = getAllowedOrigin(req, config);
  
  // SECURITY: Reject credentialed cross-origin requests from disallowed origins
  // This prevents session leakage in relaxed CORS environments (WebViews, Electron, etc.)
  if (!origin && req.headers.get('origin')) {
    // Cross-origin request from disallowed origin
    if (hasCredentials(req)) {
      console.warn('CORS violation: credentialed request from disallowed origin', {
        origin: req.headers.get('origin'),
        hasCookie: !!req.headers.get('cookie'),
        hasAuth: !!req.headers.get('authorization'),
      });
      
      return new Response(
        JSON.stringify({ error: 'Forbidden: Cross-origin request not allowed' }),
        {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }
    
    // No credentials, just return response without CORS headers
    // The browser will block access to the response, which is safe
    return response;
  }
  
  // No Origin header = same-origin request, no CORS headers needed
  if (!origin) {
    return response;
  }
  
  // Origin is allowed - add CORS headers
  const headers = new Headers(response.headers);
  
  // SECURITY: Echo exact allowed origin, never wildcard
  headers.set('Access-Control-Allow-Origin', origin);
  
  // SECURITY: Vary header ensures proper caching per origin
  headers.set('Vary', 'Origin');
  
  // SECURITY: Only include credentials header if explicitly enabled
  if (config.allowCredentials) {
    headers.set('Access-Control-Allow-Credentials', 'true');
  }
  
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
