/**
 * Tests for IPv6/IPv4 CIDR matching - Trust Boundary Security
 * 
 * These tests verify that CIDR matching is bit-accurate and prevents
 * trust boundary bypass attacks via malformed or adjacent IP addresses.
 */

import { assertEquals } from "https://deno.land/std@0.192.0/testing/asserts.ts";
import { isIpInCidr } from './ip.ts';

// ============================================================================
// IPv6 /33 BOUNDARY TESTS (CRITICAL - Trust Boundary Bypass Prevention)
// ============================================================================

Deno.test("isIpInCidr - IPv6 /33 inside range", () => {
  const cidr = '2001:db8::/33';
  
  // Inside: first 33 bits match
  // 2001:db8:0000:0000:0000:0000:0000:0001
  assertEquals(isIpInCidr('2001:db8::1', cidr), true, 'Should match inside /33');
  assertEquals(isIpInCidr('2001:db8:0:0::1', cidr), true, 'Should match inside /33 (expanded)');
  assertEquals(isIpInCidr('2001:db8:7fff:ffff:ffff:ffff:ffff:ffff', cidr), true, 'Should match at upper boundary of /33');
});

Deno.test("isIpInCidr - IPv6 /33 outside range (VULNERABILITY TEST)", () => {
  const cidr = '2001:db8::/33';
  
  // CRITICAL: Outside - bit 33 is different
  // 2001:db8:8000::1 has bit 33 set to 1, placing it outside the /33 range
  // The old vulnerable code would incorrectly classify this as trusted
  // because it only compared the first two hextets as strings
  assertEquals(isIpInCidr('2001:db8:8000::1', cidr), false, 'Should NOT match outside /33 (bit 33 set) - VULN TEST');
  assertEquals(isIpInCidr('2001:db8:ffff:ffff::1', cidr), false, 'Should NOT match outside /33');
  assertEquals(isIpInCidr('2001:db9::1', cidr), false, 'Should NOT match different subnet');
});

// ============================================================================
// IPv6 /65 BOUNDARY TESTS (CRITICAL - Non-aligned prefix)
// ============================================================================

Deno.test("isIpInCidr - IPv6 /65 inside range", () => {
  const cidr = '2001:db8:0:1::/65';
  
  // Inside: first 65 bits match (4 full hextets + 1 bit of 5th hextet)
  assertEquals(isIpInCidr('2001:db8:0:1::abcd', cidr), true, 'Should match inside /65');
  assertEquals(isIpInCidr('2001:db8:0:1:0:1:2:3', cidr), true, 'Should match inside /65');
  assertEquals(isIpInCidr('2001:db8:0:1:7fff:ffff:ffff:ffff', cidr), true, 'Should match at upper boundary of /65');
});

Deno.test("isIpInCidr - IPv6 /65 outside range (VULNERABILITY TEST)", () => {
  const cidr = '2001:db8:0:1::/65';
  
  // CRITICAL: Outside - bit 65 is different
  // 2001:db8:0:1:8000::1 has bit 65 set to 1 (5th hextet = 0x8000)
  // The vulnerable code would miss this boundary
  assertEquals(isIpInCidr('2001:db8:0:1:8000::1', cidr), false, 'Should NOT match outside /65 (bit 65 set) - VULN TEST');
  assertEquals(isIpInCidr('2001:db8:0:2::1', cidr), false, 'Should NOT match different subnet');
});

// ============================================================================
// IPv6 Compressed Notation Tests
// ============================================================================

Deno.test("isIpInCidr - IPv6 compressed notation", () => {
  const cidr = '2001:db8::/32';
  
  assertEquals(isIpInCidr('2001:db8::', cidr), true, 'Compressed form should match');
  assertEquals(isIpInCidr('2001:db8:0:0:0:0:0:0', cidr), true, 'Expanded form should match');
  assertEquals(isIpInCidr('2001:db8:1:2:3:4:5:6', cidr), true, 'Any IP in range should match');
  assertEquals(isIpInCidr('2001:db9::', cidr), false, 'Different subnet should not match');
});

// ============================================================================
// IPv4 Tests (Regression and Correctness)
// ============================================================================

Deno.test("isIpInCidr - IPv4 /8 and /16 ranges", () => {
  assertEquals(isIpInCidr('10.1.2.3', '10.0.0.0/8'), true, 'Should match /8');
  assertEquals(isIpInCidr('10.255.255.255', '10.0.0.0/8'), true, 'Should match /8 upper bound');
  assertEquals(isIpInCidr('11.0.0.1', '10.0.0.0/8'), false, 'Should not match outside /8');
  assertEquals(isIpInCidr('192.168.1.1', '192.168.0.0/16'), true, 'Should match /16');
  assertEquals(isIpInCidr('192.169.1.1', '192.168.0.0/16'), false, 'Should not match outside /16');
});

Deno.test("isIpInCidr - IPv4 /24 and /32 ranges", () => {
  assertEquals(isIpInCidr('192.0.2.100', '192.0.2.0/24'), true, 'Should match /24');
  assertEquals(isIpInCidr('192.0.3.1', '192.0.2.0/24'), false, 'Should not match outside /24');
  assertEquals(isIpInCidr('10.0.0.1', '10.0.0.1/32'), true, 'Exact IPv4 match /32');
  assertEquals(isIpInCidr('10.0.0.2', '10.0.0.1/32'), false, 'Different IPv4 /32');
});

// ============================================================================
// Edge Cases
// ============================================================================

Deno.test("isIpInCidr - /0 matches everything", () => {
  assertEquals(isIpInCidr('2001:db8::1', '::/0'), true, 'IPv6 /0 matches all');
  assertEquals(isIpInCidr('10.0.0.1', '0.0.0.0/0'), true, 'IPv4 /0 matches all');
});

Deno.test("isIpInCidr - /128 and /32 exact matches", () => {
  assertEquals(isIpInCidr('2001:db8::1', '2001:db8::1/128'), true, 'Exact IPv6 match /128');
  assertEquals(isIpInCidr('2001:db8::2', '2001:db8::1/128'), false, 'Different IPv6 /128');
  assertEquals(isIpInCidr('10.0.0.1', '10.0.0.1/32'), true, 'Exact IPv4 match /32');
  assertEquals(isIpInCidr('10.0.0.2', '10.0.0.1/32'), false, 'Different IPv4 /32');
});

Deno.test("isIpInCidr - IPv6 with zone indices", () => {
  // Zone indices (e.g., %eth0) should be stripped
  assertEquals(isIpInCidr('2001:db8::1%eth0', '2001:db8::/32'), true, 'Should strip zone index');
  assertEquals(isIpInCidr('fe80::1%lo', 'fe80::/10'), true, 'Should handle link-local with zone');
});

Deno.test("isIpInCidr - IPv4-mapped IPv6", () => {
  // ::ffff:192.0.2.1 is IPv4-mapped IPv6
  assertEquals(isIpInCidr('::ffff:192.0.2.1', '::ffff:192.0.2.0/120'), true, 'v4-mapped inside range');
  assertEquals(isIpInCidr('::ffff:192.0.3.1', '::ffff:192.0.2.0/120'), false, 'v4-mapped outside range');
});

// ============================================================================
// Invalid Inputs
// ============================================================================

Deno.test("isIpInCidr - Invalid inputs", () => {
  assertEquals(isIpInCidr('invalid', '10.0.0.0/8'), false, 'Invalid IP');
  assertEquals(isIpInCidr('10.0.0.1', 'invalid/8'), false, 'Invalid CIDR');
  assertEquals(isIpInCidr('10.0.0.1', '10.0.0.0/999'), false, 'Invalid IPv4 prefix length');
  assertEquals(isIpInCidr('2001:db8::1', '2001:db8::/999'), false, 'Invalid IPv6 prefix length');
  assertEquals(isIpInCidr('10.0.0.1', '10.0.0.0/-5'), false, 'Negative prefix length');
  assertEquals(isIpInCidr('', '10.0.0.0/8'), false, 'Empty IP');
  assertEquals(isIpInCidr('10.0.0.1', ''), false, 'Empty CIDR');
});

// ============================================================================
// Trust Boundary Integration Tests
// ============================================================================

Deno.test("Trust boundary - Attacker cannot bypass via adjacent IPv6", () => {
  // Scenario: Deployment trusts Cloudflare range 2001:db8::/33
  // Attacker connects from 2001:db8:8000::1 (outside /33 but shares hextets)
  const trustedCidr = '2001:db8::/33';
  const attackerIp = '2001:db8:8000::1';
  const legitimateIp = '2001:db8::1';
  
  assertEquals(isIpInCidr(attackerIp, trustedCidr), false, 'Attacker IP must NOT be trusted');
  assertEquals(isIpInCidr(legitimateIp, trustedCidr), true, 'Legitimate IP must be trusted');
});

Deno.test("Trust boundary - Non-aligned prefix precision", () => {
  // Multiple non-aligned prefixes to ensure bit-accurate matching
  const testCases = [
    { ip: '2001:db8:0:1:4000::1', cidr: '2001:db8:0:1::/65', expected: true },
    { ip: '2001:db8:0:1:8000::1', cidr: '2001:db8:0:1::/65', expected: false },
    { ip: '10.128.0.1', cidr: '10.0.0.0/9', expected: true },
    { ip: '10.128.0.1', cidr: '10.0.0.0/8', expected: true },
    { ip: '10.0.0.1', cidr: '10.128.0.0/9', expected: false },
  ];
  
  testCases.forEach(({ ip, cidr, expected }) => {
    assertEquals(isIpInCidr(ip, cidr), expected, `${ip} in ${cidr} should be ${expected}`);
  });
});
