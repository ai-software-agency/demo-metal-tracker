import { assertEquals } from 'https://deno.land/std@0.168.0/testing/asserts.ts';
import { handleRequest } from './index.ts';

Deno.test('auth-logout: Rejects POST without Origin or Referer', async () => {
  Deno.env.set('LOGOUT_ALLOWED_ORIGINS', 'http://localhost:8080');
  
  const req = new Request('http://localhost/auth-logout', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': 'test-token',
    },
  });

  const response = await handleRequest(req);
  assertEquals(response.status, 403);
  
  const body = await response.json();
  assertEquals(body.error, 'Forbidden');
});

Deno.test('auth-logout: Rejects POST from disallowed Origin', async () => {
  Deno.env.set('LOGOUT_ALLOWED_ORIGINS', 'http://localhost:8080');
  
  const req = new Request('http://localhost/auth-logout', {
    method: 'POST',
    headers: {
      'Origin': 'https://evil.com',
      'Content-Type': 'application/json',
      'X-CSRF-Token': 'test-token',
    },
  });

  const response = await handleRequest(req);
  assertEquals(response.status, 403);
  
  const body = await response.json();
  assertEquals(body.error, 'Forbidden');
});

Deno.test('auth-logout: Rejects POST with malformed Referer', async () => {
  Deno.env.set('LOGOUT_ALLOWED_ORIGINS', 'http://localhost:8080');
  
  const req = new Request('http://localhost/auth-logout', {
    method: 'POST',
    headers: {
      'Referer': 'not-a-valid-url',
      'Content-Type': 'application/json',
      'X-CSRF-Token': 'test-token',
    },
  });

  const response = await handleRequest(req);
  assertEquals(response.status, 403);
});

Deno.test('auth-logout: Rejects POST without CSRF cookie', async () => {
  Deno.env.set('LOGOUT_ALLOWED_ORIGINS', 'http://localhost:8080');
  
  const req = new Request('http://localhost/auth-logout', {
    method: 'POST',
    headers: {
      'Origin': 'http://localhost:8080',
      'Content-Type': 'application/json',
      'X-CSRF-Token': 'test-token',
      'Cookie': 'sb-session=fake-session',
    },
  });

  const response = await handleRequest(req);
  assertEquals(response.status, 403);
  
  const body = await response.json();
  assertEquals(body.error, 'Forbidden');
});

Deno.test('auth-logout: Rejects POST without CSRF header', async () => {
  Deno.env.set('LOGOUT_ALLOWED_ORIGINS', 'http://localhost:8080');
  
  const req = new Request('http://localhost/auth-logout', {
    method: 'POST',
    headers: {
      'Origin': 'http://localhost:8080',
      'Content-Type': 'application/json',
      'Cookie': 'sb-csrf=test-token; sb-session=fake-session',
    },
  });

  const response = await handleRequest(req);
  assertEquals(response.status, 403);
  
  const body = await response.json();
  assertEquals(body.error, 'Forbidden');
});

Deno.test('auth-logout: Rejects POST with mismatched CSRF tokens', async () => {
  Deno.env.set('LOGOUT_ALLOWED_ORIGINS', 'http://localhost:8080');
  
  const req = new Request('http://localhost/auth-logout', {
    method: 'POST',
    headers: {
      'Origin': 'http://localhost:8080',
      'Content-Type': 'application/json',
      'X-CSRF-Token': 'wrong-token',
      'Cookie': 'sb-csrf=correct-token; sb-session=fake-session',
    },
  });

  const response = await handleRequest(req);
  assertEquals(response.status, 403);
  
  const body = await response.json();
  assertEquals(body.error, 'Forbidden');
});

Deno.test('auth-logout: Accepts POST with matching CSRF tokens and allowed origin', async () => {
  Deno.env.set('LOGOUT_ALLOWED_ORIGINS', 'http://localhost:8080');
  
  const req = new Request('http://localhost/auth-logout', {
    method: 'POST',
    headers: {
      'Origin': 'http://localhost:8080',
      'Content-Type': 'application/json',
      'X-CSRF-Token': 'matching-token',
      'Cookie': 'sb-csrf=matching-token; sb-session=fake-session',
    },
  });

  const response = await handleRequest(req);
  // Should not be 403 or 405 - will proceed to logout logic (200)
  assertEquals(response.status, 200);
  
  const body = await response.json();
  assertEquals(body.success, true);
  
  // Verify both cookies are cleared
  const setCookie = response.headers.get('Set-Cookie');
  assertEquals(setCookie !== null, true);
  assertEquals(setCookie?.includes('sb-session='), true);
  assertEquals(setCookie?.includes('sb-csrf='), true);
  assertEquals(setCookie?.includes('Max-Age=0'), true);
});

Deno.test('auth-logout: Accepts POST with matching CSRF tokens via Referer', async () => {
  Deno.env.set('LOGOUT_ALLOWED_ORIGINS', 'http://localhost:8080');
  
  const req = new Request('http://localhost/auth-logout', {
    method: 'POST',
    headers: {
      'Referer': 'http://localhost:8080/some-page',
      'Content-Type': 'application/json',
      'X-CSRF-Token': 'matching-token',
      'Cookie': 'sb-csrf=matching-token; sb-session=fake-session',
    },
  });

  const response = await handleRequest(req);
  assertEquals(response.status, 200);
  
  const body = await response.json();
  assertEquals(body.success, true);
});

Deno.test('auth-logout: OPTIONS preflight includes CSRF headers in allowed headers', async () => {
  Deno.env.set('LOGOUT_ALLOWED_ORIGINS', 'http://localhost:8080');
  
  const req = new Request('http://localhost/auth-logout', {
    method: 'OPTIONS',
    headers: {
      'Origin': 'http://localhost:8080',
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'content-type,x-csrf-token',
    },
  });

  const response = await handleRequest(req);
  assertEquals(response.status, 204);
  
  const allowedHeaders = response.headers.get('Access-Control-Allow-Headers');
  assertEquals(allowedHeaders?.includes('x-csrf-token'), true);
  assertEquals(allowedHeaders?.includes('x-requested-with'), true);
  
  const allowedMethods = response.headers.get('Access-Control-Allow-Methods');
  assertEquals(allowedMethods, 'POST');
});
