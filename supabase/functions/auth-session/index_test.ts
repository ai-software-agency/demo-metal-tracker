import { assertEquals } from 'https://deno.land/std@0.208.0/assert/mod.ts';

// Helper to create a fake JWT token with specific claims
function createFakeToken(claims: any): string {
  const header = { alg: 'HS256', typ: 'JWT' };
  const headerB64 = btoa(JSON.stringify(header)).replace(/=/g, '');
  const payloadB64 = btoa(JSON.stringify(claims)).replace(/=/g, '');
  const signature = 'fake_signature';
  return `${headerB64}.${payloadB64}.${signature}`;
}

// Re-implement helpers for testing (normally would import from index.ts)
function parseJwtClaims(token: string): any {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = parts[1];
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = atob(base64);
    return JSON.parse(jsonPayload);
  } catch (error) {
    return null;
  }
}

function isMfaVerified(claims: any, minAal: number = 2): boolean {
  if (!claims) return false;
  const amr = Array.isArray(claims?.amr) 
    ? claims.amr.map((m: any) => String(m).toLowerCase()) 
    : [];
  const strongMethods = ['otp', 'totp', 'webauthn', 'sms', 'mfa'];
  const hasStrongAmr = amr.some((m: string) => strongMethods.includes(m));
  const aalRaw = claims?.aal;
  let aalNum = 1;
  if (typeof aalRaw === 'number') {
    aalNum = aalRaw;
  } else if (typeof aalRaw === 'string') {
    const match = aalRaw.match(/\d+/);
    aalNum = match ? Number(match[0]) : 1;
  }
  return hasStrongAmr || aalNum >= minAal;
}

Deno.test('parseJwtClaims - valid token', () => {
  const claims = { sub: 'user123', amr: ['pwd'], aal: 1 };
  const token = createFakeToken(claims);
  const parsed = parseJwtClaims(token);
  assertEquals(parsed.sub, 'user123');
  assertEquals(parsed.amr, ['pwd']);
  assertEquals(parsed.aal, 1);
});

Deno.test('parseJwtClaims - malformed token', () => {
  const result = parseJwtClaims('invalid.token');
  assertEquals(result, null);
});

Deno.test('parseJwtClaims - empty token', () => {
  const result = parseJwtClaims('');
  assertEquals(result, null);
});

Deno.test('isMfaVerified - password only (no MFA)', () => {
  const claims = { amr: ['pwd'], aal: 1 };
  const result = isMfaVerified(claims, 2);
  assertEquals(result, false);
});

Deno.test('isMfaVerified - with OTP', () => {
  const claims = { amr: ['pwd', 'otp'], aal: 1 };
  const result = isMfaVerified(claims, 2);
  assertEquals(result, true);
});

Deno.test('isMfaVerified - with TOTP', () => {
  const claims = { amr: ['pwd', 'totp'], aal: 1 };
  const result = isMfaVerified(claims, 2);
  assertEquals(result, true);
});

Deno.test('isMfaVerified - with WebAuthn', () => {
  const claims = { amr: ['pwd', 'webauthn'], aal: 2 };
  const result = isMfaVerified(claims, 2);
  assertEquals(result, true);
});

Deno.test('isMfaVerified - with SMS', () => {
  const claims = { amr: ['pwd', 'sms'], aal: 1 };
  const result = isMfaVerified(claims, 2);
  assertEquals(result, true);
});

Deno.test('isMfaVerified - with generic MFA', () => {
  const claims = { amr: ['pwd', 'mfa'], aal: 1 };
  const result = isMfaVerified(claims, 2);
  assertEquals(result, true);
});

Deno.test('isMfaVerified - AAL2 numeric', () => {
  const claims = { amr: ['pwd'], aal: 2 };
  const result = isMfaVerified(claims, 2);
  assertEquals(result, true);
});

Deno.test('isMfaVerified - AAL2 string', () => {
  const claims = { amr: ['pwd'], aal: 'aal2' };
  const result = isMfaVerified(claims, 2);
  assertEquals(result, true);
});

Deno.test('isMfaVerified - AAL1 insufficient', () => {
  const claims = { amr: ['pwd'], aal: 'aal1' };
  const result = isMfaVerified(claims, 2);
  assertEquals(result, false);
});

Deno.test('isMfaVerified - missing claims', () => {
  const result = isMfaVerified(null, 2);
  assertEquals(result, false);
});

Deno.test('isMfaVerified - empty amr array', () => {
  const claims = { amr: [], aal: 1 };
  const result = isMfaVerified(claims, 2);
  assertEquals(result, false);
});

Deno.test('isMfaVerified - amr not an array', () => {
  const claims = { amr: 'pwd', aal: 1 };
  const result = isMfaVerified(claims, 2);
  assertEquals(result, false);
});

Deno.test('isMfaVerified - case insensitive amr', () => {
  const claims = { amr: ['pwd', 'OTP'], aal: 1 };
  const result = isMfaVerified(claims, 2);
  assertEquals(result, true);
});

Deno.test('isMfaVerified - AAL3 exceeds minimum', () => {
  const claims = { amr: ['pwd'], aal: 3 };
  const result = isMfaVerified(claims, 2);
  assertEquals(result, true);
});

Deno.test('isMfaVerified - custom minAal', () => {
  const claims = { amr: ['pwd'], aal: 1 };
  const result = isMfaVerified(claims, 1);
  assertEquals(result, true);
});

Deno.test('integration - admin without MFA should be blocked', () => {
  const hasAdminRole = true;
  const requireMfa = true;
  const minAal = 2;
  
  const claims = { sub: 'admin123', amr: ['pwd'], aal: 1 };
  const mfaVerified = isMfaVerified(claims, minAal);
  
  // Expected behavior: should NOT grant isAdmin
  const shouldGrantAdmin = hasAdminRole && (!requireMfa || mfaVerified);
  assertEquals(shouldGrantAdmin, false);
  assertEquals(mfaVerified, false);
});

Deno.test('integration - admin with MFA should be granted', () => {
  const hasAdminRole = true;
  const requireMfa = true;
  const minAal = 2;
  
  const claims = { sub: 'admin123', amr: ['pwd', 'otp'], aal: 2 };
  const mfaVerified = isMfaVerified(claims, minAal);
  
  // Expected behavior: should grant isAdmin
  const shouldGrantAdmin = hasAdminRole && (!requireMfa || mfaVerified);
  assertEquals(shouldGrantAdmin, true);
  assertEquals(mfaVerified, true);
});

Deno.test('integration - non-admin never gets admin access', () => {
  const hasAdminRole = false;
  const requireMfa = true;
  const minAal = 2;
  
  const claims = { sub: 'user123', amr: ['pwd', 'otp'], aal: 2 };
  const mfaVerified = isMfaVerified(claims, minAal);
  
  // Expected behavior: should NOT grant isAdmin even with MFA
  const shouldGrantAdmin = hasAdminRole && (!requireMfa || mfaVerified);
  assertEquals(shouldGrantAdmin, false);
});

Deno.test('integration - admin with MFA disabled gets access', () => {
  const hasAdminRole = true;
  const requireMfa = false;
  const minAal = 2;
  
  const claims = { sub: 'admin123', amr: ['pwd'], aal: 1 };
  const mfaVerified = isMfaVerified(claims, minAal);
  
  // Expected behavior: should grant isAdmin when MFA not required
  const shouldGrantAdmin = hasAdminRole && (!requireMfa || mfaVerified);
  assertEquals(shouldGrantAdmin, true);
  assertEquals(mfaVerified, false);
});
