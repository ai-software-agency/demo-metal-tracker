/**
 * SECURITY TESTS: CORS Configuration
 * 
 * Verifies that auth-session endpoint properly enforces CORS allowlist
 * and rejects credentialed requests from disallowed origins.
 */

import { assertEquals, assertExists } from 'https://deno.land/std@0.208.0/assert/mod.ts';

const FUNCTION_URL = Deno.env.get('SUPABASE_URL')?.replace('https://', 'https://') + '/functions/v1/auth-session';
const ANON_KEY = Deno.env.get('SUPABASE_ANON_KEY') || '';

// Note: These tests verify CORS behavior. Actual enforcement happens in the browser.
// We're testing server-side headers and status codes.

Deno.test('CORS: Reject preflight from disallowed origin', async () => {
  const response = await fetch(FUNCTION_URL, {
    method: 'OPTIONS',
    headers: {
      'Origin': 'https://evil.example.com',
      'Access-Control-Request-Method': 'GET',
      'Access-Control-Request-Headers': 'authorization, content-type',
    },
  });
  
  assertEquals(response.status, 403, 'Should return 403 for disallowed origin');
  
  const acao = response.headers.get('access-control-allow-origin');
  assertEquals(acao, null, 'Should NOT include Access-Control-Allow-Origin for disallowed origin');
});

Deno.test('CORS: Reject credentialed GET from disallowed origin', async () => {
  const response = await fetch(FUNCTION_URL, {
    method: 'GET',
    headers: {
      'Origin': 'https://evil.example.com',
      'Authorization': `Bearer ${ANON_KEY}`,
      'Cookie': 'sb-session=fake-session-token',
    },
  });
  
  assertEquals(response.status, 403, 'Should return 403 for credentialed request from disallowed origin');
  
  const data = await response.json();
  assertEquals(data.error, 'Forbidden: Cross-origin request not allowed');
});

Deno.test('CORS: Accept preflight from allowed origin (localhost)', async () => {
  const response = await fetch(FUNCTION_URL, {
    method: 'OPTIONS',
    headers: {
      'Origin': 'http://localhost:8080',
      'Access-Control-Request-Method': 'GET',
      'Access-Control-Request-Headers': 'authorization, content-type',
    },
  });
  
  assertEquals(response.status, 204, 'Should return 204 for allowed origin');
  
  const acao = response.headers.get('access-control-allow-origin');
  assertEquals(acao, 'http://localhost:8080', 'Should echo exact allowed origin');
  
  const vary = response.headers.get('vary');
  assertEquals(vary, 'Origin', 'Should include Vary: Origin header');
  
  const methods = response.headers.get('access-control-allow-methods');
  assertExists(methods, 'Should include Access-Control-Allow-Methods');
  assertEquals(methods?.includes('GET'), true, 'Should allow GET method');
  assertEquals(methods?.includes('OPTIONS'), true, 'Should allow OPTIONS method');
  
  const credentials = response.headers.get('access-control-allow-credentials');
  assertEquals(credentials, 'true', 'Should allow credentials for authenticated endpoint');
});

Deno.test('CORS: No wildcard origin in responses', async () => {
  const response = await fetch(FUNCTION_URL, {
    method: 'OPTIONS',
    headers: {
      'Origin': 'http://localhost:8080',
      'Access-Control-Request-Method': 'GET',
    },
  });
  
  const acao = response.headers.get('access-control-allow-origin');
  assertEquals(acao !== '*', true, 'Should NEVER use wildcard origin');
});

Deno.test('CORS: Same-origin request works without CORS headers', async () => {
  // Request without Origin header (same-origin)
  const response = await fetch(FUNCTION_URL, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${ANON_KEY}`,
    },
  });
  
  // Should work normally (will be 401 without valid session, but that's expected)
  const validStatuses = [200, 401];
  assertEquals(validStatuses.includes(response.status), true, 'Should process same-origin request');
});

Deno.test('CORS: Allowed origin receives proper headers on GET', async () => {
  const response = await fetch(FUNCTION_URL, {
    method: 'GET',
    headers: {
      'Origin': 'http://localhost:8080',
      'Authorization': `Bearer ${ANON_KEY}`,
    },
  });
  
  // Will be 401 without valid session, but headers should be present
  const acao = response.headers.get('access-control-allow-origin');
  assertEquals(acao, 'http://localhost:8080', 'Should include ACAO for allowed origin');
  
  const vary = response.headers.get('vary');
  assertEquals(vary, 'Origin', 'Should include Vary: Origin');
  
  const credentials = response.headers.get('access-control-allow-credentials');
  assertEquals(credentials, 'true', 'Should include credentials header');
});

Deno.test('SECURITY: Verify no credentials+wildcard combination', async () => {
  // Test both preflight and actual request
  const preflightResponse = await fetch(FUNCTION_URL, {
    method: 'OPTIONS',
    headers: {
      'Origin': 'http://localhost:8080',
      'Access-Control-Request-Method': 'GET',
    },
  });
  
  const getResponse = await fetch(FUNCTION_URL, {
    method: 'GET',
    headers: {
      'Origin': 'http://localhost:8080',
      'Authorization': `Bearer ${ANON_KEY}`,
    },
  });
  
  // Check both responses
  for (const response of [preflightResponse, getResponse]) {
    const acao = response.headers.get('access-control-allow-origin');
    const acac = response.headers.get('access-control-allow-credentials');
    
    // CRITICAL: If credentials are allowed, origin MUST NOT be wildcard
    if (acac === 'true') {
      assertEquals(acao !== '*', true, 'SECURITY VIOLATION: Cannot use wildcard origin with credentials');
      assertExists(acao, 'Must have specific origin when credentials are allowed');
    }
  }
});
