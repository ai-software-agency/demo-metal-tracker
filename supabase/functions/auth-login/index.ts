import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.78.0';
import { createRateLimiter } from '../_shared/security/rateLimiter.ts';
import { RateLimitBackendUnavailable } from '../_shared/security/attemptStore.ts';
import { getClientIp } from '../_shared/util/ip.ts';
import { normalizeIdentifier } from '../_shared/util/normalize.ts';
import { preflight, withCors } from '../_shared/util/cors.ts';

// SECURITY: Maximum request body size (32KB) to prevent DoS via oversized payloads
const MAX_BODY_BYTES = 32 * 1024;

// SECURITY: Email and password constraints to prevent abuse
const EMAIL_MIN_LENGTH = 3;
const EMAIL_MAX_LENGTH = 254; // RFC 5321 standard
const PASSWORD_MIN_LENGTH = 8;
const PASSWORD_MAX_LENGTH = 256;

// Conservative email regex per RFC 5322 (basic validation)
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * SECURITY: Read request body with size limit to prevent memory exhaustion
 * Handles both Content-Length header and streaming reads for chunked encoding
 */
async function readLimitedBody(req: Request, maxBytes: number): Promise<string> {
  const contentLength = req.headers.get('content-length');
  
  // Fast path: Check Content-Length header first
  if (contentLength) {
    const length = parseInt(contentLength, 10);
    if (isNaN(length) || length < 0) {
      throw new Error('INVALID_CONTENT_LENGTH');
    }
    if (length > maxBytes) {
      throw new Error('PAYLOAD_TOO_LARGE');
    }
    // Content-Length is within limits, safe to read
    return await req.text();
  }
  
  // Slow path: Stream body for chunked transfer or missing Content-Length
  const reader = req.body?.getReader();
  if (!reader) {
    throw new Error('NO_BODY');
  }
  
  const decoder = new TextDecoder('utf-8');
  const chunks: string[] = [];
  let totalBytes = 0;
  
  try {
    while (true) {
      const { done, value } = await reader.read();
      
      if (done) break;
      
      totalBytes += value.byteLength;
      
      // SECURITY: Enforce size limit during streaming
      if (totalBytes > maxBytes) {
        reader.cancel();
        throw new Error('PAYLOAD_TOO_LARGE');
      }
      
      chunks.push(decoder.decode(value, { stream: true }));
    }
    
    // Flush remaining bytes
    chunks.push(decoder.decode());
    
    return chunks.join('');
  } catch (error) {
    reader.cancel();
    throw error;
  }
}

/**
 * SECURITY: Validate login input schema with strict type and length checks
 * Prevents injection attacks and resource exhaustion via oversized fields
 */
interface LoginInput {
  email: string;
  password: string;
}

function validateLoginInput(obj: unknown): LoginInput {
  // Type check
  if (!obj || typeof obj !== 'object') {
    throw new Error('INVALID_JSON_OBJECT');
  }
  
  const { email, password } = obj as Record<string, unknown>;
  
  // Required fields
  if (!email || !password) {
    throw new Error('MISSING_FIELDS');
  }
  
  // Type validation
  if (typeof email !== 'string' || typeof password !== 'string') {
    throw new Error('INVALID_FIELD_TYPES');
  }
  
  // Normalize and validate email
  const normalizedEmail = email.trim().toLowerCase();
  
  if (normalizedEmail.length < EMAIL_MIN_LENGTH || normalizedEmail.length > EMAIL_MAX_LENGTH) {
    throw new Error('INVALID_EMAIL_LENGTH');
  }
  
  if (!EMAIL_REGEX.test(normalizedEmail)) {
    throw new Error('INVALID_EMAIL_FORMAT');
  }
  
  // Validate password length (don't normalize password - preserve original)
  if (password.length < PASSWORD_MIN_LENGTH || password.length > PASSWORD_MAX_LENGTH) {
    throw new Error('INVALID_PASSWORD_LENGTH');
  }
  
  return {
    email: normalizedEmail,
    password: password,
  };
}

/**
 * Handle login request with rate limiting and secure session management
 * Implements per-IP and per-identifier throttling with exponential backoff
 * 
 * SECURITY FEATURES:
 * - Request size limiting (pre-parse and streaming)
 * - Method validation (POST only)
 * - Content-Type validation
 * - Schema validation with length constraints
 * - Rate limiting per IP and email
 */
export async function handleLogin(req: Request): Promise<Response> {
  // SECURITY: Enforce POST method only
  if (req.method !== 'POST') {
    return withCors(
      req,
      new Response(
        JSON.stringify({ error: 'Method Not Allowed' }),
        { 
          status: 405, 
          headers: { 
            'Content-Type': 'application/json',
            'Allow': 'POST'
          } 
        }
      )
    );
  }
  
  // SECURITY: Validate Content-Type
  const contentType = req.headers.get('content-type')?.toLowerCase() || '';
  if (!contentType.startsWith('application/json')) {
    return withCors(
      req,
      new Response(
        JSON.stringify({ error: 'Unsupported Media Type. Content-Type must be application/json' }),
        { status: 415, headers: { 'Content-Type': 'application/json' } }
      )
    );
  }

  const supabaseClient = createClient(
    Deno.env.get('SUPABASE_URL') ?? '',
    Deno.env.get('SUPABASE_ANON_KEY') ?? '',
  );

  const rateLimiter = createRateLimiter(supabaseClient);

  try {
    // SECURITY: Read body with size limit to prevent memory exhaustion
    let bodyText: string;
    try {
      bodyText = await readLimitedBody(req, MAX_BODY_BYTES);
    } catch (error) {
      if (error instanceof Error) {
        if (error.message === 'PAYLOAD_TOO_LARGE') {
          return withCors(
            req,
            new Response(
              JSON.stringify({ 
                error: 'Payload Too Large',
                message: `Request body must not exceed ${MAX_BODY_BYTES} bytes`
              }),
              { status: 413, headers: { 'Content-Type': 'application/json' } }
            )
          );
        }
        if (error.message === 'NO_BODY' || error.message === 'INVALID_CONTENT_LENGTH') {
          return withCors(
            req,
            new Response(
              JSON.stringify({ error: 'Bad Request', message: 'Invalid or missing request body' }),
              { status: 400, headers: { 'Content-Type': 'application/json' } }
            )
          );
        }
      }
      throw error;
    }
    
    // SECURITY: Parse JSON safely
    let parsedBody: unknown;
    try {
      parsedBody = JSON.parse(bodyText);
    } catch {
      return withCors(
        req,
        new Response(
          JSON.stringify({ error: 'Bad Request', message: 'Invalid JSON' }),
          { status: 400, headers: { 'Content-Type': 'application/json' } }
        )
      );
    }
    
    // SECURITY: Validate input schema with strict type and length checks
    let input: LoginInput;
    try {
      input = validateLoginInput(parsedBody);
    } catch (error) {
      if (error instanceof Error) {
        const errorMessages: Record<string, string> = {
          'INVALID_JSON_OBJECT': 'Request body must be a JSON object',
          'MISSING_FIELDS': 'Email and password are required',
          'INVALID_FIELD_TYPES': 'Email and password must be strings',
          'INVALID_EMAIL_LENGTH': `Email must be between ${EMAIL_MIN_LENGTH} and ${EMAIL_MAX_LENGTH} characters`,
          'INVALID_EMAIL_FORMAT': 'Invalid email format',
          'INVALID_PASSWORD_LENGTH': `Password must be between ${PASSWORD_MIN_LENGTH} and ${PASSWORD_MAX_LENGTH} characters`,
        };
        
        const message = errorMessages[error.message] || 'Invalid request format';
        
        return withCors(
          req,
          new Response(
            JSON.stringify({ error: 'Bad Request', message }),
            { status: 400, headers: { 'Content-Type': 'application/json' } }
          )
        );
      }
      throw error;
    }
    
    const { email, password } = input;

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
