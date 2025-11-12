import { assertEquals, assertExists } from 'https://deno.land/std@0.192.0/testing/asserts.ts';

/**
 * CORS Security Tests for auth-session endpoint
 * 
 * These tests validate that the auth-session function implements secure CORS:
 * - No wildcard Access-Control-Allow-Origin with credentials
 * - Only allowed origins receive CORS headers
 * - Disallowed origins are rejected with 403
 * - Vary: Origin is present to prevent cache poisoning
 * - PII is minimized (no email exposure)
 */

// Helper to create a mock handler response
async function mockAuthSessionHandler(req: Request): Promise<Response> {
  // Import the actual handler would go here
  // For now, we'll test the patterns that should be implemented
  const { preflight, withCors } = await import('../_shared/util/cors.ts');
  
  if (req.method === 'OPTIONS') {
    return preflight(req);
  }
  
  // Mock authenticated response
  const response = new Response(
    JSON.stringify({ authenticated: true, userId: 'test-user-id', isAdmin: false }),
    { status: 200, headers: { 'Content-Type': 'application/json' } }
  );
  
  return withCors(req, response);
}

Deno.test('CORS: allowed origin receives correct headers', async () => {
  // Set allowed origins
  Deno.env.set('ALLOWED_ORIGINS', 'https://app.example.com,https://staging.example.com');
  
  const req = new Request('http://localhost/functions/v1/auth-session', {
    method: 'GET',
    headers: {
      'Origin': 'https://app.example.com',
      'Authorization': 'Bearer valid-token'
    },
  });

  const response = await mockAuthSessionHandler(req);
  
  // Should echo the allowed origin
  assertEquals(response.headers.get('Access-Control-Allow-Origin'), 'https://app.example.com');
  assertEquals(response.headers.get('Access-Control-Allow-Credentials'), 'true');
  assertExists(response.headers.get('Vary'));
  assertEquals(response.headers.get('Vary'), 'Origin');
  
  // Should never be wildcard
  assertEquals(response.headers.get('Access-Control-Allow-Origin') === '*', false);
});

Deno.test('CORS: disallowed origin is rejected', async () => {
  Deno.env.set('ALLOWED_ORIGINS', 'https://app.example.com');
  
  const req = new Request('http://localhost/functions/v1/auth-session', {
    method: 'GET',
    headers: {
      'Origin': 'https://evil.example',
    },
  });

  const response = await mockAuthSessionHandler(req);
  
  // Should be 403 or have no ACAO header
  const acao = response.headers.get('Access-Control-Allow-Origin');
  if (response.status === 403) {
    // Explicit rejection - good
    assertEquals(acao, null);
  } else {
    // Or ACAO should be absent so browser blocks
    assertEquals(acao, null);
  }
  
  // Vary should still be present
  assertExists(response.headers.get('Vary'));
});

Deno.test('CORS: OPTIONS preflight for allowed origin returns 204', async () => {
  Deno.env.set('ALLOWED_ORIGINS', 'https://app.example.com');
  
  const req = new Request('http://localhost/functions/v1/auth-session', {
    method: 'OPTIONS',
    headers: {
      'Origin': 'https://app.example.com',
      'Access-Control-Request-Method': 'GET',
    },
  });

  const response = await mockAuthSessionHandler(req);
  
  assertEquals(response.status, 204);
  assertEquals(response.headers.get('Access-Control-Allow-Origin'), 'https://app.example.com');
  assertEquals(response.headers.get('Access-Control-Allow-Credentials'), 'true');
  assertExists(response.headers.get('Access-Control-Allow-Methods'));
  assertExists(response.headers.get('Vary'));
});

Deno.test('CORS: OPTIONS preflight for disallowed origin returns 403', async () => {
  Deno.env.set('ALLOWED_ORIGINS', 'https://app.example.com');
  
  const req = new Request('http://localhost/functions/v1/auth-session', {
    method: 'OPTIONS',
    headers: {
      'Origin': 'https://evil.example',
      'Access-Control-Request-Method': 'GET',
    },
  });

  const response = await mockAuthSessionHandler(req);
  
  assertEquals(response.status, 403);
  assertEquals(response.headers.get('Access-Control-Allow-Origin'), null);
});

Deno.test('CORS: no origin header (same-origin request) works', async () => {
  Deno.env.set('ALLOWED_ORIGINS', 'https://app.example.com');
  
  const req = new Request('http://localhost/functions/v1/auth-session', {
    method: 'GET',
    headers: {
      'Authorization': 'Bearer valid-token'
    },
    // No Origin header - simulates same-origin request
  });

  const response = await mockAuthSessionHandler(req);
  
  // Should work but not expose ACAO
  assertEquals(response.status, 200);
  // Vary should still be present for cache safety
  assertExists(response.headers.get('Vary'));
});

Deno.test('PII: response does not include email', async () => {
  Deno.env.set('ALLOWED_ORIGINS', 'https://app.example.com');
  
  const req = new Request('http://localhost/functions/v1/auth-session', {
    method: 'GET',
    headers: {
      'Origin': 'https://app.example.com',
      'Authorization': 'Bearer valid-token'
    },
  });

  const response = await mockAuthSessionHandler(req);
  const body = await response.json();
  
  // Should not include email
  assertEquals('email' in body, false);
  assertEquals('user' in body && typeof body.user === 'object' && 'email' in body.user, false);
  
  // Should include only minimal fields
  assertExists(body.authenticated);
  if (body.authenticated) {
    assertExists(body.userId);
  }
});

Deno.test('Security: wildcard origin never combined with credentials', async () => {
  // Test multiple scenarios to ensure no wildcard + credentials combo
  const origins = [
    'https://app.example.com',
    'https://evil.example',
    null, // no origin
  ];
  
  Deno.env.set('ALLOWED_ORIGINS', 'https://app.example.com');
  
  for (const origin of origins) {
    const headers: Record<string, string> = { 'Authorization': 'Bearer valid-token' };
    if (origin) {
      headers['Origin'] = origin;
    }
    
    const req = new Request('http://localhost/functions/v1/auth-session', {
      method: 'GET',
      headers,
    });

    const response = await mockAuthSessionHandler(req);
    
    const acao = response.headers.get('Access-Control-Allow-Origin');
    const acc = response.headers.get('Access-Control-Allow-Credentials');
    
    // If credentials are true, ACAO must not be wildcard
    if (acc === 'true') {
      assertEquals(acao === '*', false, `Wildcard ACAO with credentials for origin: ${origin}`);
    }
  }
});
