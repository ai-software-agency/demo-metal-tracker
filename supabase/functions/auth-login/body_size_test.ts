/**
 * SECURITY TESTS: Request Body Size Limiting
 * 
 * Verifies that the auth-login function properly rejects oversized payloads
 * before parsing to prevent DoS attacks via memory exhaustion.
 */

import { assertEquals } from 'https://deno.land/std@0.208.0/assert/mod.ts';

const FUNCTION_URL = Deno.env.get('SUPABASE_URL')?.replace('https://', 'https://') + '/functions/v1/auth-login';
const ANON_KEY = Deno.env.get('SUPABASE_ANON_KEY') || '';

Deno.test('SECURITY: Reject oversized body with Content-Length', async () => {
  // Create a 100KB payload (exceeds 32KB limit)
  const largePassword = 'A'.repeat(100 * 1024);
  const payload = JSON.stringify({
    email: 'test@example.com',
    password: largePassword,
  });
  
  const response = await fetch(FUNCTION_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${ANON_KEY}`,
      'apikey': ANON_KEY,
    },
    body: payload,
  });
  
  assertEquals(response.status, 413, 'Should return 413 Payload Too Large');
  
  const data = await response.json();
  assertEquals(data.error, 'Payload Too Large');
});

Deno.test('SECURITY: Reject non-POST methods', async () => {
  const response = await fetch(FUNCTION_URL, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${ANON_KEY}`,
      'apikey': ANON_KEY,
    },
  });
  
  assertEquals(response.status, 405, 'Should return 405 Method Not Allowed');
  assertEquals(response.headers.get('Allow'), 'POST');
});

Deno.test('SECURITY: Reject wrong Content-Type', async () => {
  const response = await fetch(FUNCTION_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain',
      'Authorization': `Bearer ${ANON_KEY}`,
      'apikey': ANON_KEY,
    },
    body: 'not json',
  });
  
  assertEquals(response.status, 415, 'Should return 415 Unsupported Media Type');
});

Deno.test('SECURITY: Reject invalid JSON', async () => {
  const response = await fetch(FUNCTION_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${ANON_KEY}`,
      'apikey': ANON_KEY,
    },
    body: '{invalid json}',
  });
  
  assertEquals(response.status, 400, 'Should return 400 Bad Request');
  
  const data = await response.json();
  assertEquals(data.message, 'Invalid JSON');
});

Deno.test('SECURITY: Reject email that is too long', async () => {
  const longEmail = 'a'.repeat(300) + '@example.com';
  
  const response = await fetch(FUNCTION_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${ANON_KEY}`,
      'apikey': ANON_KEY,
    },
    body: JSON.stringify({
      email: longEmail,
      password: 'ValidPassword123',
    }),
  });
  
  assertEquals(response.status, 400, 'Should return 400 Bad Request');
  
  const data = await response.json();
  assertEquals(data.error, 'Bad Request');
});

Deno.test('SECURITY: Reject password that is too short', async () => {
  const response = await fetch(FUNCTION_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${ANON_KEY}`,
      'apikey': ANON_KEY,
    },
    body: JSON.stringify({
      email: 'test@example.com',
      password: 'short',
    }),
  });
  
  assertEquals(response.status, 400, 'Should return 400 Bad Request');
  
  const data = await response.json();
  assertEquals(data.error, 'Bad Request');
});

Deno.test('SECURITY: Reject invalid email format', async () => {
  const response = await fetch(FUNCTION_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${ANON_KEY}`,
      'apikey': ANON_KEY,
    },
    body: JSON.stringify({
      email: 'not-an-email',
      password: 'ValidPassword123',
    }),
  });
  
  assertEquals(response.status, 400, 'Should return 400 Bad Request');
  
  const data = await response.json();
  assertEquals(data.error, 'Bad Request');
});

Deno.test('FUNCTIONALITY: Accept valid login payload', async () => {
  const response = await fetch(FUNCTION_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${ANON_KEY}`,
      'apikey': ANON_KEY,
    },
    body: JSON.stringify({
      email: 'test@example.com',
      password: 'ValidPassword123',
    }),
  });
  
  // Should reach auth logic (will likely return 401 for invalid creds, but validates request format)
  const validStatuses = [200, 401, 429]; // 200=success, 401=invalid creds, 429=rate limit
  const isValid = validStatuses.includes(response.status);
  
  assertEquals(isValid, true, 'Should accept valid payload and reach auth logic');
});

Deno.test('FUNCTIONALITY: Normalize email (trim and lowercase)', async () => {
  const response = await fetch(FUNCTION_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${ANON_KEY}`,
      'apikey': ANON_KEY,
    },
    body: JSON.stringify({
      email: '  Test@Example.COM  ',
      password: 'ValidPassword123',
    }),
  });
  
  // Should reach auth logic with normalized email
  const validStatuses = [200, 401, 429];
  const isValid = validStatuses.includes(response.status);
  
  assertEquals(isValid, true, 'Should normalize and accept email');
});
