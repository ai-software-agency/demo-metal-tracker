/**
 * CORS Security Helper
 * 
 * Implements strict CORS controls based on an allowlist from environment variables.
 * Prevents unauthorized cross-origin access to sensitive endpoints.
 * 
 * Environment Variables:
 * - ALLOWED_ORIGINS: Comma-separated list of allowed origins (e.g., "https://example.com,https://app.example.com")
 *                    If not set, defaults to local development origins for safety
 */

interface CorsConfig {
  allowedOrigins: string[];
  allowedMethods: string[];
  allowedHeaders: string[];
}

/**
 * Load CORS configuration from environment
 */
function getConfig(): CorsConfig {
  const originsEnv = Deno.env.get('ALLOWED_ORIGINS');
  
  // Default to local development origins if not configured
  // NEVER default to '*' for security
  const defaultOrigins = [
    'http://localhost:8080',
    'http://localhost:5173',
    'http://127.0.0.1:8080',
    'http://127.0.0.1:5173',
  ];
  
  const allowedOrigins = originsEnv
    ? originsEnv.split(',').map(o => o.trim()).filter(o => o.length > 0)
    : defaultOrigins;
  
  return {
    allowedOrigins,
    allowedMethods: ['POST', 'OPTIONS'],
    allowedHeaders: ['authorization', 'x-client-info', 'apikey', 'content-type'],
  };
}

/**
 * Get the allowed origin for a request, or null if origin is not allowed
 */
export function getAllowedOrigin(req: Request): string | null {
  const origin = req.headers.get('origin');
  if (!origin) {
    return null;
  }
  
  const config = getConfig();
  if (config.allowedOrigins.includes(origin)) {
    return origin;
  }
  
  return null;
}

/**
 * Handle CORS preflight OPTIONS request
 * Returns 204 if origin is allowed, 403 otherwise
 */
export function preflight(req: Request): Response {
  const origin = getAllowedOrigin(req);
  
  if (!origin) {
    return new Response(null, { 
      status: 403,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  const config = getConfig();
  
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': config.allowedMethods.join(', '),
      'Access-Control-Allow-Headers': config.allowedHeaders.join(', '),
      'Access-Control-Max-Age': '86400', // 24 hours
      'Vary': 'Origin',
    },
  });
}

/**
 * Apply CORS headers to a response if origin is allowed
 */
export function withCors(req: Request, response: Response): Response {
  const origin = getAllowedOrigin(req);
  
  if (!origin) {
    // Origin not allowed - return response without CORS headers
    return response;
  }
  
  // Clone the response to add headers
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', origin);
  headers.set('Vary', 'Origin');
  
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
