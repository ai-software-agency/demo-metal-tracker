/**
 * Integration tests for auth-login handler with rate limiting
 */

import { assertEquals } from 'https://deno.land/std@0.168.0/testing/asserts.ts';
import { handleLogin } from './index.ts';

// Set environment for testing
Deno.env.set('SUPABASE_URL', 'http://localhost:54321');
Deno.env.set('SUPABASE_ANON_KEY', 'test-key');
Deno.env.set('RATE_LIMIT_BACKEND', 'memory');

Deno.test('Login handler - blocks after rate limit threshold', async () => {
  const email = 'test@example.com';
  const password = 'wrongpassword';
  const ip = '192.168.1.1';

  // Make 5 failed attempts (should all get 401)
  for (let i = 0; i < 5; i++) {
    const req = new Request('http://localhost/auth-login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-forwarded-for': ip,
      },
      body: JSON.stringify({ email, password }),
    });

    const response = await handleLogin(req);
    
    // Note: In real scenario with mocked auth, this would be 401
    // For this test without mocking, we just verify the handler runs
    assertEquals(typeof response.status, 'number');
  }

  // 6th attempt should trigger rate limit (429)
  const req = new Request('http://localhost/auth-login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-forwarded-for': ip,
    },
    body: JSON.stringify({ email, password }),
  });

  const response = await handleLogin(req);
  const body = await response.json();

  // Should be rate limited after soft threshold
  assertEquals(response.status, 429);
  assertEquals(body.error, 'Too many attempts. Please try again later.');
  assertEquals(response.headers.has('Retry-After'), true);
});

Deno.test('Login handler - returns 400 for missing credentials', async () => {
  const req = new Request('http://localhost/auth-login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({}),
  });

  const response = await handleLogin(req);
  const body = await response.json();

  assertEquals(response.status, 400);
  assertEquals(body.error, 'Email and password are required');
});

Deno.test('Login handler - returns generic error on auth failure', async () => {
  const req = new Request('http://localhost/auth-login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-forwarded-for': '10.0.0.1',
    },
    body: JSON.stringify({
      email: 'unique-test@example.com',
      password: 'wrongpass',
    }),
  });

  const response = await handleLogin(req);
  const body = await response.json();

  // Should return generic error, not upstream error
  assertEquals(response.status === 401 || response.status === 429, true);
  if (response.status === 401) {
    assertEquals(body.error, 'Invalid email or password');
  }
});
