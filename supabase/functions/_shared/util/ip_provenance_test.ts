/**
 * Security Tests for Trust Boundary Enforcement in IP Extraction
 * 
 * Run with: deno test supabase/functions/_shared/util/ip_provenance_test.ts
 * 
 * These tests verify that proxy headers are ONLY trusted when
 * provenance is properly verified via CIDR allowlist or shared secret.
 */

import { assertEquals } from "https://deno.land/std@0.192.0/testing/asserts.ts";
import { getClientIp } from "./ip.ts";

function createRequest(headers: Record<string, string>): Request {
  const h = new Headers();
  for (const [key, value] of Object.entries(headers)) {
    h.set(key, value);
  }
  return new Request('http://localhost', { headers: h });
}

// ============================================================================
// SECURITY TESTS: Trust Boundary Bypass Prevention
// ============================================================================

Deno.test("Security - Cloudflare headers ignored without provenance", () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'cloudflare');
  Deno.env.delete('TRUSTED_PROXY_CIDRS');
  Deno.env.delete('TRUSTED_PROXY_SECRET');
  
  const req = createRequest({
    'cf-connecting-ip': '8.8.8.8',
    'cf-ray': '12345-SEA',
  });
  
  // Without provenance (no CIDR match, no secret), CF headers should be ignored
  const ip = getClientIp(req);
  assertEquals(ip, null, 'Should ignore cf-connecting-ip without provenance');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
});

Deno.test("Security - Cloudflare headers trusted with CIDR provenance", () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'cloudflare');
  Deno.env.set('TRUSTED_PROXY_CIDRS', '203.0.113.0/24');
  
  const req = createRequest({
    'cf-connecting-ip': '8.8.8.8',
    'cf-ray': '12345-SEA',
  });
  
  // Simulate request from trusted proxy IP within CIDR
  const peerIp = '203.0.113.50';
  const ip = getClientIp(req, peerIp);
  
  assertEquals(ip, '8.8.8.8', 'Should trust cf-connecting-ip with CIDR provenance');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_PROXY_CIDRS');
});

Deno.test("Security - Cloudflare headers trusted with shared secret", () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'cloudflare');
  Deno.env.set('TRUSTED_PROXY_SECRET', 'my-secret-token');
  Deno.env.set('TRUSTED_PROXY_SECRET_HEADER', 'x-proxy-verified');
  
  const req = createRequest({
    'cf-connecting-ip': '8.8.8.8',
    'cf-ray': '12345-SEA',
    'x-proxy-verified': 'my-secret-token',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, '8.8.8.8', 'Should trust cf-connecting-ip with valid shared secret');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_PROXY_SECRET');
  Deno.env.delete('TRUSTED_PROXY_SECRET_HEADER');
});

Deno.test("Security - Cloudflare headers ignored with wrong shared secret", () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'cloudflare');
  Deno.env.set('TRUSTED_PROXY_SECRET', 'correct-secret');
  
  const req = createRequest({
    'cf-connecting-ip': '8.8.8.8',
    'cf-ray': '12345-SEA',
    'x-proxy-verified': 'wrong-secret',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, null, 'Should ignore cf-connecting-ip with invalid shared secret');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_PROXY_SECRET');
});

Deno.test("Security - XFF headers ignored without provenance", () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'xff');
  Deno.env.set('TRUSTED_HOPS', '1');
  Deno.env.delete('TRUSTED_PROXY_CIDRS');
  Deno.env.delete('TRUSTED_PROXY_SECRET');
  
  const req = createRequest({
    'x-forwarded-for': '198.51.100.77, 203.0.113.45',
  });
  
  // Without provenance, XFF headers should be ignored
  const ip = getClientIp(req);
  assertEquals(ip, null, 'Should ignore x-forwarded-for without provenance');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_HOPS');
});

Deno.test("Security - XFF headers trusted with CIDR provenance", () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'xff');
  Deno.env.set('TRUSTED_HOPS', '1');
  Deno.env.set('TRUSTED_PROXY_CIDRS', '192.0.2.0/24');
  
  const req = createRequest({
    'x-forwarded-for': '198.51.100.77, 203.0.113.45',
  });
  
  // Simulate request from trusted proxy IP
  const peerIp = '192.0.2.100';
  const ip = getClientIp(req, peerIp);
  
  assertEquals(ip, '198.51.100.77', 'Should trust XFF with CIDR provenance');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_HOPS');
  Deno.env.delete('TRUSTED_PROXY_CIDRS');
});

Deno.test("Security - XFF headers trusted with shared secret", () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'xff');
  Deno.env.set('TRUSTED_HOPS', '1');
  Deno.env.set('TRUSTED_PROXY_SECRET', 'load-balancer-secret');
  
  const req = createRequest({
    'x-forwarded-for': '198.51.100.77, 203.0.113.45',
    'x-proxy-verified': 'load-balancer-secret',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, '198.51.100.77', 'Should trust XFF with valid shared secret');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_HOPS');
  Deno.env.delete('TRUSTED_PROXY_SECRET');
});

Deno.test("Security - Attacker cannot spoof allowlisted IP via headers", () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'cloudflare');
  Deno.env.set('TRUSTED_PROXY_CIDRS', '203.0.113.0/24');
  
  const req = createRequest({
    'cf-connecting-ip': '203.0.113.100', // Trying to claim allowlisted IP
    'cf-ray': 'fake-ray',
  });
  
  // Request actually from untrusted source
  const peerIp = '198.51.100.1'; // NOT in 203.0.113.0/24
  const ip = getClientIp(req, peerIp);
  
  // Should return the actual peer IP, not the spoofed cf-connecting-ip
  assertEquals(ip, '198.51.100.1', 'Should use peer IP when provenance fails');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_PROXY_CIDRS');
});

Deno.test("Security - Multiple CIDR blocks supported", () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'cloudflare');
  Deno.env.set('TRUSTED_PROXY_CIDRS', '203.0.113.0/24,198.51.100.0/24,192.0.2.0/24');
  
  const req = createRequest({
    'cf-connecting-ip': '8.8.8.8',
    'cf-ray': '12345-SEA',
  });
  
  // Test with IP from second CIDR block
  const peerIp = '198.51.100.50';
  const ip = getClientIp(req, peerIp);
  
  assertEquals(ip, '8.8.8.8', 'Should trust when peer IP in any configured CIDR');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_PROXY_CIDRS');
});

Deno.test("Security - IPv6 CIDR provenance verification", () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'cloudflare');
  Deno.env.set('TRUSTED_PROXY_CIDRS', '2001:db8::/32');
  
  const req = createRequest({
    'cf-connecting-ip': '8.8.8.8',
    'cf-ray': '12345-SEA',
  });
  
  // Peer IP from IPv6 trusted CIDR
  const peerIp = '2001:db8::1234';
  const ip = getClientIp(req, peerIp);
  
  assertEquals(ip, '8.8.8.8', 'Should support IPv6 CIDR verification');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_PROXY_CIDRS');
});

// ============================================================================
// FUNCTIONALITY TESTS: Correct Behavior When Provenance Verified
// ============================================================================

Deno.test("Functionality - Peer IP returned when provenance fails", () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'cloudflare');
  Deno.env.delete('TRUSTED_PROXY_CIDRS');
  Deno.env.delete('TRUSTED_PROXY_SECRET');
  
  const req = createRequest({
    'cf-connecting-ip': '8.8.8.8',
    'cf-ray': '12345-SEA',
  });
  
  const peerIp = '198.51.100.1';
  const ip = getClientIp(req, peerIp);
  
  // When provenance fails, should fall back to peer IP
  assertEquals(ip, '198.51.100.1', 'Should return peer IP when proxy headers untrusted');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
});

Deno.test("Functionality - Private IPs rejected even with provenance", () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'cloudflare');
  Deno.env.set('TRUSTED_PROXY_CIDRS', '203.0.113.0/24');
  Deno.env.delete('ALLOW_PRIVATE_IPS');
  
  const req = createRequest({
    'cf-connecting-ip': '10.0.0.1', // Private IP
    'cf-ray': '12345-SEA',
  });
  
  const peerIp = '203.0.113.50';
  const ip = getClientIp(req, peerIp);
  
  assertEquals(ip, null, 'Should reject private IP even with verified provenance');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_PROXY_CIDRS');
});

Deno.test("Functionality - None mode returns peer IP regardless of headers", () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'none');
  
  const req = createRequest({
    'cf-connecting-ip': '8.8.8.8',
    'x-forwarded-for': '1.1.1.1',
    'cf-ray': '12345-SEA',
  });
  
  const peerIp = '198.51.100.1';
  const ip = getClientIp(req, peerIp);
  
  assertEquals(ip, '198.51.100.1', 'None mode should return peer IP, ignoring all headers');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
});

// ============================================================================
// EDGE CASES
// ============================================================================

Deno.test("Edge case - Malformed CIDR gracefully handled", () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'cloudflare');
  Deno.env.set('TRUSTED_PROXY_CIDRS', 'invalid-cidr,203.0.113.0/24');
  
  const req = createRequest({
    'cf-connecting-ip': '8.8.8.8',
    'cf-ray': '12345-SEA',
  });
  
  const peerIp = '203.0.113.50';
  const ip = getClientIp(req, peerIp);
  
  // Should still work with valid CIDR, ignoring invalid one
  assertEquals(ip, '8.8.8.8', 'Should handle malformed CIDR gracefully');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_PROXY_CIDRS');
});

Deno.test("Edge case - Empty CIDR list behaves safely", () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'cloudflare');
  Deno.env.set('TRUSTED_PROXY_CIDRS', '');
  Deno.env.delete('TRUSTED_PROXY_SECRET');
  
  const req = createRequest({
    'cf-connecting-ip': '8.8.8.8',
    'cf-ray': '12345-SEA',
  });
  
  const peerIp = '198.51.100.1';
  const ip = getClientIp(req, peerIp);
  
  // Without CIDRs or secret, should fall back to peer IP
  assertEquals(ip, '198.51.100.1', 'Empty CIDR list should not grant trust');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_PROXY_CIDRS');
});

Deno.test("Edge case - Custom secret header name respected", () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'cloudflare');
  Deno.env.set('TRUSTED_PROXY_SECRET', 'test-secret');
  Deno.env.set('TRUSTED_PROXY_SECRET_HEADER', 'x-custom-auth');
  
  const req = createRequest({
    'cf-connecting-ip': '8.8.8.8',
    'cf-ray': '12345-SEA',
    'x-custom-auth': 'test-secret',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, '8.8.8.8', 'Should use custom secret header name');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_PROXY_SECRET');
  Deno.env.delete('TRUSTED_PROXY_SECRET_HEADER');
});

Deno.test("Edge case - Provenance via CIDR OR secret (not both required)", () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'cloudflare');
  Deno.env.set('TRUSTED_PROXY_CIDRS', '203.0.113.0/24');
  Deno.env.set('TRUSTED_PROXY_SECRET', 'secret123');
  
  // Request 1: Matches CIDR but not secret
  const req1 = createRequest({
    'cf-connecting-ip': '8.8.8.8',
    'cf-ray': '12345-SEA',
    'x-proxy-verified': 'wrong-secret',
  });
  const ip1 = getClientIp(req1, '203.0.113.50');
  assertEquals(ip1, '8.8.8.8', 'CIDR match alone should be sufficient');
  
  // Request 2: Matches secret but not CIDR
  const req2 = createRequest({
    'cf-connecting-ip': '1.1.1.1',
    'cf-ray': '67890-LAX',
    'x-proxy-verified': 'secret123',
  });
  const ip2 = getClientIp(req2, '198.51.100.1');
  assertEquals(ip2, '1.1.1.1', 'Secret match alone should be sufficient');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_PROXY_CIDRS');
  Deno.env.delete('TRUSTED_PROXY_SECRET');
});
