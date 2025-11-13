/**
 * Unit Tests for Step-Up Authentication Logic
 * 
 * Tests the MFA/AAL2 and recency validation for admin privilege checks.
 * These tests verify that only sessions with proper step-up authentication
 * (multi-factor + recent auth) can assert admin privileges.
 */

import { assertEquals, assertExists } from 'https://deno.land/std@0.208.0/assert/mod.ts';

/**
 * Helper: Create a base64url-encoded JWT with custom payload
 */
function createTestJwt(payload: any): string {
  const header = { alg: 'HS256', typ: 'JWT' };
  
  const encodeBase64Url = (obj: any): string => {
    const json = JSON.stringify(obj);
    const base64 = btoa(json);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };
  
  const headerB64 = encodeBase64Url(header);
  const payloadB64 = encodeBase64Url(payload);
  const signature = 'fake_signature';
  
  return `${headerB64}.${payloadB64}.${signature}`;
}

/**
 * Decode JWT payload (copy of function from index.ts for testing)
 */
function decodeJwtPayload(token: string): any {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    const payload = parts[1];
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + (4 - (base64.length % 4)) % 4, '=');
    const jsonString = atob(padded);
    
    return JSON.parse(jsonString);
  } catch {
    return null;
  }
}

/**
 * Check AAL2 (copy of function from index.ts for testing)
 */
function isAAL2(payload: any): boolean {
  if (!payload) return false;
  if (payload.aal === 'aal2') return true;
  
  if (Array.isArray(payload.amr)) {
    const mfaMethods = ['mfa', 'totp', 'webauthn', 'otp', 'sms'];
    return payload.amr.some((method: string) => 
      mfaMethods.includes(method.toLowerCase())
    );
  }
  
  return false;
}

/**
 * Check recent auth (copy of function from index.ts for testing)
 */
function isRecentAuth(payload: any, maxAgeSeconds: number): boolean {
  if (!payload) return false;
  
  const now = Math.floor(Date.now() / 1000);
  const authTime = payload.auth_time || payload.iat;
  
  if (!authTime || typeof authTime !== 'number') return false;
  
  const age = now - authTime;
  return age >= 0 && age <= maxAgeSeconds;
}

// Test Suite: JWT Decoding
Deno.test('decodeJwtPayload: valid JWT with standard claims', () => {
  const payload = {
    sub: 'user-123',
    email: 'test@example.com',
    aal: 'aal2',
    iat: Math.floor(Date.now() / 1000),
  };
  
  const token = createTestJwt(payload);
  const decoded = decodeJwtPayload(token);
  
  assertExists(decoded);
  assertEquals(decoded.sub, 'user-123');
  assertEquals(decoded.email, 'test@example.com');
  assertEquals(decoded.aal, 'aal2');
});

Deno.test('decodeJwtPayload: malformed token returns null', () => {
  const malformed = 'not.a.valid.jwt.token';
  const decoded = decodeJwtPayload(malformed);
  assertEquals(decoded, null);
});

Deno.test('decodeJwtPayload: token with only two parts returns null', () => {
  const invalid = 'header.payload';
  const decoded = decodeJwtPayload(invalid);
  assertEquals(decoded, null);
});

// Test Suite: AAL2 Detection
Deno.test('isAAL2: detects aal2 claim', () => {
  const payload = { aal: 'aal2' };
  assertEquals(isAAL2(payload), true);
});

Deno.test('isAAL2: detects mfa in amr array', () => {
  const payload = { amr: ['pwd', 'mfa'] };
  assertEquals(isAAL2(payload), true);
});

Deno.test('isAAL2: detects totp in amr array', () => {
  const payload = { amr: ['pwd', 'totp'] };
  assertEquals(isAAL2(payload), true);
});

Deno.test('isAAL2: detects webauthn in amr array', () => {
  const payload = { amr: ['webauthn'] };
  assertEquals(isAAL2(payload), true);
});

Deno.test('isAAL2: rejects aal1 without MFA methods', () => {
  const payload = { aal: 'aal1', amr: ['pwd'] };
  assertEquals(isAAL2(payload), false);
});

Deno.test('isAAL2: rejects payload without aal or amr', () => {
  const payload = { sub: 'user-123' };
  assertEquals(isAAL2(payload), false);
});

Deno.test('isAAL2: rejects null payload', () => {
  assertEquals(isAAL2(null), false);
});

// Test Suite: Recent Authentication
Deno.test('isRecentAuth: accepts recent auth_time within maxAge', () => {
  const now = Math.floor(Date.now() / 1000);
  const payload = { auth_time: now - 300 }; // 5 minutes ago
  assertEquals(isRecentAuth(payload, 600), true);
});

Deno.test('isRecentAuth: rejects stale auth_time beyond maxAge', () => {
  const now = Math.floor(Date.now() / 1000);
  const payload = { auth_time: now - 700 }; // 11.6 minutes ago
  assertEquals(isRecentAuth(payload, 600), false);
});

Deno.test('isRecentAuth: falls back to iat when auth_time missing', () => {
  const now = Math.floor(Date.now() / 1000);
  const payload = { iat: now - 200 }; // 3.3 minutes ago
  assertEquals(isRecentAuth(payload, 600), true);
});

Deno.test('isRecentAuth: rejects stale iat', () => {
  const now = Math.floor(Date.now() / 1000);
  const payload = { iat: now - 800 }; // 13.3 minutes ago
  assertEquals(isRecentAuth(payload, 600), false);
});

Deno.test('isRecentAuth: rejects payload without auth_time or iat', () => {
  const payload = { sub: 'user-123' };
  assertEquals(isRecentAuth(payload, 600), false);
});

Deno.test('isRecentAuth: rejects null payload', () => {
  assertEquals(isRecentAuth(null, 600), false);
});

Deno.test('isRecentAuth: rejects future timestamps', () => {
  const now = Math.floor(Date.now() / 1000);
  const payload = { auth_time: now + 300 }; // 5 minutes in the future
  assertEquals(isRecentAuth(payload, 600), false);
});

// Test Suite: Integration - Full Step-Up Validation
Deno.test('integration: valid AAL2 + recent auth should pass', () => {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: 'admin-user',
    aal: 'aal2',
    auth_time: now - 100,
  };
  
  assertEquals(isAAL2(payload), true);
  assertEquals(isRecentAuth(payload, 600), true);
});

Deno.test('integration: AAL2 but stale auth should fail recency check', () => {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: 'admin-user',
    aal: 'aal2',
    auth_time: now - 700,
  };
  
  assertEquals(isAAL2(payload), true);
  assertEquals(isRecentAuth(payload, 600), false);
});

Deno.test('integration: recent auth but no MFA should fail AAL2 check', () => {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: 'admin-user',
    aal: 'aal1',
    amr: ['pwd'],
    auth_time: now - 100,
  };
  
  assertEquals(isAAL2(payload), false);
  assertEquals(isRecentAuth(payload, 600), true);
});

Deno.test('integration: MFA via amr + recent iat should pass', () => {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: 'admin-user',
    amr: ['pwd', 'totp'],
    iat: now - 200,
  };
  
  assertEquals(isAAL2(payload), true);
  assertEquals(isRecentAuth(payload, 600), true);
});
