import { assertEquals } from 'https://deno.land/std@0.168.0/testing/asserts.ts';
import { handleRequest } from './index.ts';

Deno.test('auth-logout: Rejects GET requests with 405', async () => {
  const req = new Request('http://localhost/auth-logout', {
    method: 'GET',
    headers: {
      'Origin': 'http://localhost:8080',
    },
  });

  const response = await handleRequest(req);
  assertEquals(response.status, 405);
  assertEquals(response.headers.get('Allow'), 'POST');
  
  const body = await response.json();
  assertEquals(body.error, 'Method not allowed');
});

Deno.test('auth-logout: Rejects PUT requests with 405', async () => {
  const req = new Request('http://localhost/auth-logout', {
    method: 'PUT',
    headers: {
      'Origin': 'http://localhost:8080',
    },
  });

  const response = await handleRequest(req);
  assertEquals(response.status, 405);
  assertEquals(response.headers.get('Allow'), 'POST');
});

Deno.test('auth-logout: Rejects DELETE requests with 405', async () => {
  const req = new Request('http://localhost/auth-logout', {
    method: 'DELETE',
    headers: {
      'Origin': 'http://localhost:8080',
    },
  });

  const response = await handleRequest(req);
  assertEquals(response.status, 405);
});

Deno.test('auth-logout: Allows POST requests to proceed to origin validation', async () => {
  // Set required env var for test
  Deno.env.set('LOGOUT_ALLOWED_ORIGINS', 'http://localhost:8080');
  
  const req = new Request('http://localhost/auth-logout', {
    method: 'POST',
    headers: {
      'Origin': 'http://localhost:8080',
      'Content-Type': 'application/json',
    },
  });

  const response = await handleRequest(req);
  // Should not be 405, will proceed to normal logout flow (may be 200 or other status)
  assertEquals(response.status !== 405, true);
});

Deno.test('auth-logout: POST from disallowed origin is rejected with 403', async () => {
  Deno.env.set('LOGOUT_ALLOWED_ORIGINS', 'http://localhost:8080');
  
  const req = new Request('http://localhost/auth-logout', {
    method: 'POST',
    headers: {
      'Origin': 'https://evil.com',
      'Content-Type': 'application/json',
    },
  });

  const response = await handleRequest(req);
  assertEquals(response.status, 403);
  
  const body = await response.json();
  assertEquals(body.error, 'Forbidden');
});
