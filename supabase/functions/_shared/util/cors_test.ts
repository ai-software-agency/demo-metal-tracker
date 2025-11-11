import { assertEquals, assertExists } from 'https://deno.land/std@0.208.0/assert/mod.ts';
import { getAllowedOrigin, preflight, withCors } from './cors.ts';

Deno.test('getAllowedOrigin - returns origin when allowed', () => {
  // Set up test environment
  Deno.env.set('ALLOWED_ORIGINS', 'https://example.com,http://localhost:3000');
  
  const req = new Request('https://test.com', {
    headers: { 'origin': 'https://example.com' }
  });
  
  const result = getAllowedOrigin(req);
  assertEquals(result, 'https://example.com');
  
  // Cleanup
  Deno.env.delete('ALLOWED_ORIGINS');
});

Deno.test('getAllowedOrigin - returns null when not allowed', () => {
  Deno.env.set('ALLOWED_ORIGINS', 'https://example.com');
  
  const req = new Request('https://test.com', {
    headers: { 'origin': 'https://evil.com' }
  });
  
  const result = getAllowedOrigin(req);
  assertEquals(result, null);
  
  Deno.env.delete('ALLOWED_ORIGINS');
});

Deno.test('getAllowedOrigin - returns null when no origin header', () => {
  Deno.env.set('ALLOWED_ORIGINS', 'https://example.com');
  
  const req = new Request('https://test.com');
  
  const result = getAllowedOrigin(req);
  assertEquals(result, null);
  
  Deno.env.delete('ALLOWED_ORIGINS');
});

Deno.test('getAllowedOrigin - uses default localhost origins when ALLOWED_ORIGINS not set', () => {
  Deno.env.delete('ALLOWED_ORIGINS');
  
  const req = new Request('https://test.com', {
    headers: { 'origin': 'http://localhost:5173' }
  });
  
  const result = getAllowedOrigin(req);
  assertEquals(result, 'http://localhost:5173');
});

Deno.test('preflight - returns 204 with CORS headers for allowed origin', () => {
  Deno.env.set('ALLOWED_ORIGINS', 'https://example.com');
  
  const req = new Request('https://test.com', {
    method: 'OPTIONS',
    headers: { 
      'origin': 'https://example.com',
      'access-control-request-method': 'POST',
      'access-control-request-headers': 'content-type'
    }
  });
  
  const response = preflight(req);
  
  assertEquals(response.status, 204);
  assertEquals(response.headers.get('Access-Control-Allow-Origin'), 'https://example.com');
  assertEquals(response.headers.get('Access-Control-Allow-Credentials'), 'true');
  assertEquals(response.headers.get('Access-Control-Allow-Methods'), 'POST, OPTIONS');
  assertEquals(response.headers.get('Access-Control-Allow-Headers'), 'content-type');
  assertEquals(response.headers.get('Vary'), 'Origin');
  assertExists(response.headers.get('Access-Control-Max-Age'));
  
  Deno.env.delete('ALLOWED_ORIGINS');
});

Deno.test('preflight - returns 403 for disallowed origin', () => {
  Deno.env.set('ALLOWED_ORIGINS', 'https://example.com');
  
  const req = new Request('https://test.com', {
    method: 'OPTIONS',
    headers: { 
      'origin': 'https://evil.com',
      'access-control-request-method': 'POST'
    }
  });
  
  const response = preflight(req);
  
  assertEquals(response.status, 403);
  assertEquals(response.headers.get('Access-Control-Allow-Origin'), null);
  
  Deno.env.delete('ALLOWED_ORIGINS');
});

Deno.test('preflight - returns 403 for no origin header', () => {
  Deno.env.set('ALLOWED_ORIGINS', 'https://example.com');
  
  const req = new Request('https://test.com', {
    method: 'OPTIONS'
  });
  
  const response = preflight(req);
  
  assertEquals(response.status, 403);
  
  Deno.env.delete('ALLOWED_ORIGINS');
});

Deno.test('withCors - adds CORS headers for allowed origin', () => {
  Deno.env.set('ALLOWED_ORIGINS', 'https://example.com');
  
  const req = new Request('https://test.com', {
    headers: { 'origin': 'https://example.com' }
  });
  
  const originalResponse = new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' }
  });
  
  const response = withCors(req, originalResponse);
  
  assertEquals(response.status, 200);
  assertEquals(response.headers.get('Access-Control-Allow-Origin'), 'https://example.com');
  assertEquals(response.headers.get('Access-Control-Allow-Credentials'), 'true');
  assertEquals(response.headers.get('Vary'), 'Origin');
  assertEquals(response.headers.get('Content-Type'), 'application/json');
  
  Deno.env.delete('ALLOWED_ORIGINS');
});

Deno.test('withCors - does not add CORS headers for disallowed origin', () => {
  Deno.env.set('ALLOWED_ORIGINS', 'https://example.com');
  
  const req = new Request('https://test.com', {
    headers: { 'origin': 'https://evil.com' }
  });
  
  const originalResponse = new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' }
  });
  
  const response = withCors(req, originalResponse);
  
  assertEquals(response.status, 200);
  assertEquals(response.headers.get('Access-Control-Allow-Origin'), null);
  assertEquals(response.headers.get('Access-Control-Allow-Credentials'), null);
  assertEquals(response.headers.get('Content-Type'), 'application/json');
  
  Deno.env.delete('ALLOWED_ORIGINS');
});

Deno.test('withCors - preserves original response body and headers', () => {
  Deno.env.set('ALLOWED_ORIGINS', 'https://example.com');
  
  const req = new Request('https://test.com', {
    headers: { 'origin': 'https://example.com' }
  });
  
  const originalResponse = new Response(JSON.stringify({ data: 'test' }), {
    status: 201,
    headers: { 
      'Content-Type': 'application/json',
      'X-Custom-Header': 'custom-value'
    }
  });
  
  const response = withCors(req, originalResponse);
  
  assertEquals(response.status, 201);
  assertEquals(response.headers.get('Content-Type'), 'application/json');
  assertEquals(response.headers.get('X-Custom-Header'), 'custom-value');
  
  Deno.env.delete('ALLOWED_ORIGINS');
});

Deno.test('CORS - never returns wildcard origin', () => {
  Deno.env.set('ALLOWED_ORIGINS', 'https://example.com,http://localhost:3000');
  
  // Test preflight
  const preflightReq = new Request('https://test.com', {
    method: 'OPTIONS',
    headers: { 
      'origin': 'https://example.com',
      'access-control-request-method': 'POST'
    }
  });
  
  const preflightResponse = preflight(preflightReq);
  const preflightOrigin = preflightResponse.headers.get('Access-Control-Allow-Origin');
  assertEquals(preflightOrigin !== '*', true, 'Preflight should not return wildcard origin');
  
  // Test withCors
  const req = new Request('https://test.com', {
    headers: { 'origin': 'https://example.com' }
  });
  
  const originalResponse = new Response('test');
  const corsResponse = withCors(req, originalResponse);
  const corsOrigin = corsResponse.headers.get('Access-Control-Allow-Origin');
  assertEquals(corsOrigin !== '*', true, 'withCors should not return wildcard origin');
  
  Deno.env.delete('ALLOWED_ORIGINS');
});

Deno.test('CORS - credentials never combined with wildcard', () => {
  Deno.env.set('ALLOWED_ORIGINS', 'https://example.com');
  
  const req = new Request('https://test.com', {
    headers: { 'origin': 'https://example.com' }
  });
  
  const preflightReq = new Request('https://test.com', {
    method: 'OPTIONS',
    headers: { 
      'origin': 'https://example.com',
      'access-control-request-method': 'POST'
    }
  });
  
  const preflightResponse = preflight(preflightReq);
  const preflightOrigin = preflightResponse.headers.get('Access-Control-Allow-Origin');
  const preflightCreds = preflightResponse.headers.get('Access-Control-Allow-Credentials');
  
  // If credentials are set, origin must not be wildcard
  if (preflightCreds === 'true') {
    assertEquals(preflightOrigin !== '*', true, 'Credentials must not be combined with wildcard origin');
  }
  
  const originalResponse = new Response('test');
  const corsResponse = withCors(req, originalResponse);
  const corsOrigin = corsResponse.headers.get('Access-Control-Allow-Origin');
  const corsCreds = corsResponse.headers.get('Access-Control-Allow-Credentials');
  
  if (corsCreds === 'true') {
    assertEquals(corsOrigin !== '*', true, 'Credentials must not be combined with wildcard origin');
  }
  
  Deno.env.delete('ALLOWED_ORIGINS');
});
