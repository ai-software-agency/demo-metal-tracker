import { assertEquals } from 'https://deno.land/std@0.192.0/testing/asserts.ts';

Deno.test('auth-session: rejects request without Authorization header', async () => {
  const req = new Request('http://localhost/functions/v1/auth-session', {
    method: 'GET',
  });

  // Mock the handler - in real tests, you'd import handleRequest
  // For now, this is a placeholder test structure
  const response = await fetch(req);
  
  assertEquals(response.status, 401);
  const body = await response.json();
  assertEquals(body.error, 'Unauthorized');
});

Deno.test('auth-session: rejects request with invalid Authorization header', async () => {
  const req = new Request('http://localhost/functions/v1/auth-session', {
    method: 'GET',
    headers: {
      'Authorization': 'Bearer invalid-token',
    },
  });

  const response = await fetch(req);
  
  assertEquals(response.status, 401);
  const body = await response.json();
  assertEquals(body.error, 'Unauthorized');
});

Deno.test('auth-session: rejects request with malformed Authorization header', async () => {
  const req = new Request('http://localhost/functions/v1/auth-session', {
    method: 'GET',
    headers: {
      'Authorization': 'NotBearer token',
    },
  });

  const response = await fetch(req);
  
  assertEquals(response.status, 401);
  const body = await response.json();
  assertEquals(body.error, 'Unauthorized');
});

Deno.test('auth-session: handles OPTIONS preflight correctly', async () => {
  const req = new Request('http://localhost/functions/v1/auth-session', {
    method: 'OPTIONS',
  });

  const response = await fetch(req);
  
  // OPTIONS should return 200/204 with CORS headers, not 401
  assertEquals([200, 204].includes(response.status), true);
});
