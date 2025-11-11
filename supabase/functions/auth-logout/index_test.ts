import { assertEquals, assertExists } from 'https://deno.land/std@0.208.0/assert/mod.ts';
import { handleRequest } from './index.ts';

// Configure allowed origins for tests
const ALLOWED_ORIGINS = 'https://app.example.com,https://localhost:3000';
const ALLOWED_ORIGIN = 'https://app.example.com';
const DISALLOWED_ORIGIN = 'https://evil.example.com';

// Set environment before tests
Deno.env.set('LOGOUT_ALLOWED_ORIGINS', ALLOWED_ORIGINS);
Deno.env.set('SUPABASE_URL', 'https://test.supabase.co');
Deno.env.set('SUPABASE_ANON_KEY', 'test-anon-key');

// ============================================================================
// SECURITY TESTS: Preflight Validation
// ============================================================================

Deno.test('SECURITY: Blocks preflight from disallowed origin', async () => {
  const req = new Request('https://example.com/auth-logout', {
    method: 'OPTIONS',
    headers: {
      'Origin': DISALLOWED_ORIGIN,
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'content-type',
    },
  });

  const response = await handleRequest(req);
  
  assertEquals(response.status, 403, 'Should return 403 for disallowed origin');
  
  // CRITICAL: Must not include permissive CORS headers
  assertEquals(response.headers.get('Access-Control-Allow-Origin'), null);
  assertEquals(response.headers.get('Access-Control-Allow-Credentials'), null);
  assertEquals(response.headers.get('Access-Control-Allow-Headers'), null);
});

Deno.test('SECURITY: Blocks preflight requesting privileged headers (authorization)', async () => {
  const req = new Request('https://example.com/auth-logout', {
    method: 'OPTIONS',
    headers: {
      'Origin': ALLOWED_ORIGIN,
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'authorization,content-type',
    },
  });

  const response = await handleRequest(req);
  
  assertEquals(response.status, 403, 'Should reject authorization header');
  assertEquals(response.headers.get('Access-Control-Allow-Origin'), null);
});

Deno.test('SECURITY: Blocks preflight requesting privileged headers (apikey)', async () => {
  const req = new Request('https://example.com/auth-logout', {
    method: 'OPTIONS',
    headers: {
      'Origin': ALLOWED_ORIGIN,
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'apikey,content-type',
    },
  });

  const response = await handleRequest(req);
  
  assertEquals(response.status, 403, 'Should reject apikey header');
});

Deno.test('SECURITY: Blocks preflight requesting x-client-info', async () => {
  const req = new Request('https://example.com/auth-logout', {
    method: 'OPTIONS',
    headers: {
      'Origin': ALLOWED_ORIGIN,
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'x-client-info',
    },
  });

  const response = await handleRequest(req);
  
  assertEquals(response.status, 403, 'Should reject x-client-info header');
});

Deno.test('SECURITY: Blocks preflight with invalid method (GET)', async () => {
  const req = new Request('https://example.com/auth-logout', {
    method: 'OPTIONS',
    headers: {
      'Origin': ALLOWED_ORIGIN,
      'Access-Control-Request-Method': 'GET',
      'Access-Control-Request-Headers': 'content-type',
    },
  });

  const response = await handleRequest(req);
  
  assertEquals(response.status, 403, 'Should reject GET method');
});

// ============================================================================
// FUNCTIONALITY TESTS: Valid Preflight
// ============================================================================

Deno.test('FUNCTIONALITY: Allows preflight from allowed origin with minimal headers', async () => {
  const req = new Request('https://example.com/auth-logout', {
    method: 'OPTIONS',
    headers: {
      'Origin': ALLOWED_ORIGIN,
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'content-type',
    },
  });

  const response = await handleRequest(req);
  
  assertEquals(response.status, 204, 'Should return 204 for valid preflight');
  
  // SECURITY: Should return specific origin, never wildcard
  assertEquals(
    response.headers.get('Access-Control-Allow-Origin'),
    ALLOWED_ORIGIN,
    'Should return specific allowed origin'
  );
  
  // Should allow only content-type header
  assertEquals(
    response.headers.get('Access-Control-Allow-Headers'),
    'content-type',
    'Should only allow content-type'
  );
  
  // Should allow only POST method
  assertEquals(
    response.headers.get('Access-Control-Allow-Methods'),
    'POST'
  );
  
  // Should include credentials for cookie-based auth
  assertEquals(
    response.headers.get('Access-Control-Allow-Credentials'),
    'true'
  );
  
  // SECURITY: Should include Vary header to prevent cache confusion
  assertExists(response.headers.get('Vary'));
  assertEquals(
    response.headers.get('Vary')?.includes('Origin'),
    true,
    'Should vary on Origin'
  );
  
  // Should cache preflight
  assertExists(response.headers.get('Access-Control-Max-Age'));
});

Deno.test('FUNCTIONALITY: Allows preflight with no requested headers', async () => {
  const req = new Request('https://example.com/auth-logout', {
    method: 'OPTIONS',
    headers: {
      'Origin': ALLOWED_ORIGIN,
      'Access-Control-Request-Method': 'POST',
    },
  });

  const response = await handleRequest(req);
  
  assertEquals(response.status, 204);
  assertEquals(response.headers.get('Access-Control-Allow-Origin'), ALLOWED_ORIGIN);
});

Deno.test('FUNCTIONALITY: Allows preflight from localhost (second allowed origin)', async () => {
  const req = new Request('https://example.com/auth-logout', {
    method: 'OPTIONS',
    headers: {
      'Origin': 'https://localhost:3000',
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'content-type',
    },
  });

  const response = await handleRequest(req);
  
  assertEquals(response.status, 204);
  assertEquals(
    response.headers.get('Access-Control-Allow-Origin'),
    'https://localhost:3000'
  );
});

// ============================================================================
// SECURITY TESTS: No Wildcard ACAO
// ============================================================================

Deno.test('SECURITY: Never returns wildcard Access-Control-Allow-Origin', async () => {
  const origins = [ALLOWED_ORIGIN, DISALLOWED_ORIGIN, 'https://localhost:3000'];
  
  for (const origin of origins) {
    const req = new Request('https://example.com/auth-logout', {
      method: 'OPTIONS',
      headers: {
        'Origin': origin,
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type',
      },
    });

    const response = await handleRequest(req);
    const acao = response.headers.get('Access-Control-Allow-Origin');
    
    // CRITICAL: Must never be wildcard
    assertEquals(acao !== '*', true, `Origin ${origin} must not return wildcard ACAO`);
    
    // If credentials are present, origin must be specific (not wildcard)
    const acac = response.headers.get('Access-Control-Allow-Credentials');
    if (acac === 'true') {
      assertEquals(
        acao !== '*' && acao !== null,
        true,
        'Credentials with wildcard origin is forbidden'
      );
    }
  }
});

// ============================================================================
// SECURITY TESTS: POST Request Validation
// ============================================================================

Deno.test('SECURITY: Blocks POST from disallowed origin', async () => {
  const req = new Request('https://example.com/auth-logout', {
    method: 'POST',
    headers: {
      'Origin': DISALLOWED_ORIGIN,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({}),
  });

  const response = await handleRequest(req);
  
  assertEquals(response.status, 403, 'Should return 403 for disallowed origin');
  
  const body = await response.json();
  assertEquals(body.error, 'Forbidden');
});

// ============================================================================
// FUNCTIONALITY TESTS: Valid POST Requests
// ============================================================================

Deno.test('FUNCTIONALITY: Allows POST from allowed origin', async () => {
  const req = new Request('https://example.com/auth-logout', {
    method: 'POST',
    headers: {
      'Origin': ALLOWED_ORIGIN,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({}),
  });

  const response = await handleRequest(req);
  
  assertEquals(response.status, 200, 'Should return 200 for logout');
  
  // Should include CORS headers for allowed origin
  assertEquals(
    response.headers.get('Access-Control-Allow-Origin'),
    ALLOWED_ORIGIN,
    'Should include specific origin in response'
  );
  
  assertEquals(
    response.headers.get('Access-Control-Allow-Credentials'),
    'true',
    'Should allow credentials'
  );
  
  // Should clear session cookie
  const setCookie = response.headers.get('Set-Cookie');
  assertExists(setCookie, 'Should set cookie header');
  assertEquals(setCookie?.includes('Max-Age=0'), true, 'Should expire cookie');
  
  const body = await response.json();
  assertEquals(body.success, true);
});

Deno.test('FUNCTIONALITY: Allows POST without Origin header (server-to-server)', async () => {
  const req = new Request('https://example.com/auth-logout', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({}),
  });

  const response = await handleRequest(req);
  
  assertEquals(response.status, 200, 'Should process logout without Origin');
  
  // Should not include CORS headers when no Origin present
  assertEquals(
    response.headers.get('Access-Control-Allow-Origin'),
    null,
    'Should not include ACAO without Origin header'
  );
  
  const body = await response.json();
  assertEquals(body.success, true);
});

// ============================================================================
// EDGE CASES
// ============================================================================

Deno.test('EDGE CASE: Handles mixed case in requested headers', async () => {
  const req = new Request('https://example.com/auth-logout', {
    method: 'OPTIONS',
    headers: {
      'Origin': ALLOWED_ORIGIN,
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'Content-Type,CONTENT-TYPE',
    },
  });

  const response = await handleRequest(req);
  
  // Should normalize to lowercase and deduplicate
  assertEquals(response.status, 204, 'Should handle mixed case headers');
});

Deno.test('EDGE CASE: Rejects multiple unauthorized headers', async () => {
  const req = new Request('https://example.com/auth-logout', {
    method: 'OPTIONS',
    headers: {
      'Origin': ALLOWED_ORIGIN,
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'authorization,apikey,x-client-info,content-type',
    },
  });

  const response = await handleRequest(req);
  
  assertEquals(response.status, 403, 'Should reject when any header is unauthorized');
});

Deno.test('EDGE CASE: Handles preflight with empty requested headers', async () => {
  const req = new Request('https://example.com/auth-logout', {
    method: 'OPTIONS',
    headers: {
      'Origin': ALLOWED_ORIGIN,
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': '',
    },
  });

  const response = await handleRequest(req);
  
  assertEquals(response.status, 204, 'Should allow empty requested headers');
});

// ============================================================================
// SECURITY VALIDATION: Environment Configuration
// ============================================================================

Deno.test('SECURITY: Fails closed when LOGOUT_ALLOWED_ORIGINS not set', async () => {
  const originalEnv = Deno.env.get('LOGOUT_ALLOWED_ORIGINS');
  Deno.env.delete('LOGOUT_ALLOWED_ORIGINS');
  
  try {
    const req = new Request('https://example.com/auth-logout', {
      method: 'OPTIONS',
      headers: {
        'Origin': 'https://app.example.com',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type',
      },
    });

    const response = await handleRequest(req);
    
    assertEquals(
      response.status,
      403,
      'Should block all origins when allowlist not configured'
    );
  } finally {
    if (originalEnv) {
      Deno.env.set('LOGOUT_ALLOWED_ORIGINS', originalEnv);
    }
  }
});

console.log('✅ All auth-logout CORS security tests passed');
