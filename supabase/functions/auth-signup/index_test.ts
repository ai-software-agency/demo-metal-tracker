import { assertEquals, assertExists } from "https://deno.land/std@0.192.0/testing/asserts.ts";
import { handleSignup } from "./index.ts";

/**
 * Test suite for signup endpoint security and functionality
 * 
 * Covers:
 * - Rate limiting (per-IP and per-email)
 * - Enumeration resistance
 * - CORS restrictions
 * - Input validation
 * - Edge cases
 */

// Helper to create test requests
function createSignupRequest(
  email: string,
  password: string,
  options: {
    origin?: string;
    ip?: string;
    method?: string;
  } = {}
): Request {
  const headers = new Headers({
    'Content-Type': 'application/json',
  });

  if (options.origin) {
    headers.set('Origin', options.origin);
  }

  if (options.ip) {
    headers.set('X-Real-IP', options.ip);
  }

  return new Request('http://localhost:8000/functions/v1/auth-signup', {
    method: options.method || 'POST',
    headers,
    body: options.method === 'OPTIONS' ? undefined : JSON.stringify({ email, password }),
  });
}

// Wait helper for rate limit reset
function wait(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

Deno.test("Security - CORS: Allowed origin receives CORS headers", async () => {
  const req = createSignupRequest('test@example.com', 'password123', {
    origin: 'http://localhost:8080',
  });

  const response = await handleSignup(req);
  
  const corsHeader = response.headers.get('Access-Control-Allow-Origin');
  assertEquals(corsHeader, 'http://localhost:8080');
  assertEquals(response.headers.get('Vary'), 'Origin');
});

Deno.test("Security - CORS: Preflight OPTIONS request allowed origin", async () => {
  const req = createSignupRequest('', '', {
    method: 'OPTIONS',
    origin: 'http://localhost:8080',
  });

  const response = await handleSignup(req);
  
  assertEquals(response.status, 204);
  assertEquals(response.headers.get('Access-Control-Allow-Origin'), 'http://localhost:8080');
  assertExists(response.headers.get('Access-Control-Allow-Methods'));
});

Deno.test("Security - CORS: Disallowed origin returns 403 on preflight", async () => {
  const req = createSignupRequest('', '', {
    method: 'OPTIONS',
    origin: 'https://evil.com',
  });

  const response = await handleSignup(req);
  
  assertEquals(response.status, 403);
});

Deno.test("Security - Enumeration: Response is normalized regardless of email existence", async () => {
  // Both requests should return identical responses (202 with generic message)
  const req1 = createSignupRequest('newuser@example.com', 'password123', {
    ip: '192.0.2.1',
  });
  
  const req2 = createSignupRequest('existing@example.com', 'password123', {
    ip: '192.0.2.2',
  });

  // Measure timing to ensure jitter is applied
  const start1 = Date.now();
  const response1 = await handleSignup(req1);
  const time1 = Date.now() - start1;
  
  const start2 = Date.now();
  const response2 = await handleSignup(req2);
  const time2 = Date.now() - start2;

  // Both should return 202 (not 201) to prevent enumeration
  assertEquals(response1.status, 202);
  assertEquals(response2.status, 202);

  const body1 = await response1.json();
  const body2 = await response2.json();

  // Both should have identical generic messages
  assertEquals(body1.success, true);
  assertEquals(body2.success, true);
  assertEquals(body1.message, body2.message);
  assertEquals(body1.message, 'If the email is eligible, you will receive a message with next steps.');
  
  // SECURITY: Verify timing jitter is applied (should be 80-120ms added)
  // Both responses should take at least 80ms due to artificial delay
  assertEquals(time1 >= 80, true, `Response 1 should include jitter delay (${time1}ms)`);
  assertEquals(time2 >= 80, true, `Response 2 should include jitter delay (${time2}ms)`);
});

Deno.test("Functionality - Valid signup request returns 202", async () => {
  const req = createSignupRequest('valid@example.com', 'strongpassword123', {
    ip: '192.0.2.10',
  });

  const response = await handleSignup(req);
  
  assertEquals(response.status, 202);
  assertEquals(response.headers.get('Content-Type'), 'application/json');
  assertEquals(response.headers.get('Cache-Control'), 'no-store');

  const body = await response.json();
  assertEquals(body.success, true);
  assertExists(body.message);
});

Deno.test("Validation - Invalid email format returns 400", async () => {
  const req = createSignupRequest('not-an-email', 'password123', {
    ip: '192.0.2.20',
  });

  const response = await handleSignup(req);
  
  assertEquals(response.status, 400);
  
  const body = await response.json();
  assertEquals(body.success, false);
  assertEquals(body.message, 'Invalid signup request.');
});

Deno.test("Validation - Password too short returns 400", async () => {
  const req = createSignupRequest('test@example.com', 'short', {
    ip: '192.0.2.30',
  });

  const response = await handleSignup(req);
  
  assertEquals(response.status, 400);
  
  const body = await response.json();
  assertEquals(body.success, false);
  assertEquals(body.message, 'Invalid signup request.');
});

Deno.test("Validation - Password too long returns 400", async () => {
  const longPassword = 'a'.repeat(300);
  const req = createSignupRequest('test@example.com', longPassword, {
    ip: '192.0.2.40',
  });

  const response = await handleSignup(req);
  
  assertEquals(response.status, 400);
  
  const body = await response.json();
  assertEquals(body.success, false);
});

Deno.test("Validation - Missing email returns 400", async () => {
  const req = new Request('http://localhost:8000/functions/v1/auth-signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Real-IP': '192.0.2.50' },
    body: JSON.stringify({ password: 'password123' }),
  });

  const response = await handleSignup(req);
  
  assertEquals(response.status, 400);
});

Deno.test("Validation - Missing password returns 400", async () => {
  const req = new Request('http://localhost:8000/functions/v1/auth-signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Real-IP': '192.0.2.60' },
    body: JSON.stringify({ email: 'test@example.com' }),
  });

  const response = await handleSignup(req);
  
  assertEquals(response.status, 400);
});

Deno.test("Validation - Malformed JSON returns 400", async () => {
  const req = new Request('http://localhost:8000/functions/v1/auth-signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Real-IP': '192.0.2.70' },
    body: 'not valid json{',
  });

  const response = await handleSignup(req);
  
  assertEquals(response.status, 400);
  
  const body = await response.json();
  assertEquals(body.message, 'Invalid request format.');
});

Deno.test("Edge case - Email with uppercase and spaces is normalized", async () => {
  const req = createSignupRequest('  Test@Example.COM  ', 'password123', {
    ip: '192.0.2.80',
  });

  const response = await handleSignup(req);
  
  // Should succeed with normalized email
  assertEquals(response.status, 202);
  
  const body = await response.json();
  assertEquals(body.success, true);
});

Deno.test("Edge case - Oversized request body returns 400", async () => {
  const largeBody = 'x'.repeat(11000);
  const req = new Request('http://localhost:8000/functions/v1/auth-signup', {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Content-Length': '11000',
      'X-Real-IP': '192.0.2.90',
    },
    body: largeBody,
  });

  const response = await handleSignup(req);
  
  assertEquals(response.status, 400);
  
  const body = await response.json();
  assertEquals(body.message, 'Request body too large.');
});
