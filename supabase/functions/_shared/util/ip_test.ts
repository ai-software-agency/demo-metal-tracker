/**
 * Security tests for client IP extraction
 */

import { assertEquals } from 'https://deno.land/std@0.168.0/testing/asserts.ts';
import { getClientIp } from './ip.ts';

// Helper to create mock request with headers
function createRequest(headers: Record<string, string>): Request {
  return new Request('http://localhost', {
    headers: new Headers(headers),
  });
}

// Test: Default mode (none) - rejects all client-provided headers
Deno.test('Default mode (none) - ignores x-forwarded-for', () => {
  const req = createRequest({
    'x-forwarded-for': '203.0.113.10',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, null, 'Should return null in default none mode');
});

Deno.test('Default mode (none) - ignores cf-connecting-ip without verification', () => {
  const req = createRequest({
    'cf-connecting-ip': '198.51.100.77',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, null, 'Should return null without Cloudflare verification');
});

// Test: Cloudflare mode - security validation
Deno.test('Cloudflare mode - accepts cf-connecting-ip with cf-ray present', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'cloudflare');
  
  const req = createRequest({
    'cf-connecting-ip': '198.51.100.77',
    'cf-ray': '1234567890-SJC',
    'x-forwarded-for': '203.0.113.10', // Spoofed, should be ignored
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, '198.51.100.77', 'Should use cf-connecting-ip when Cloudflare verified');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
});

Deno.test('Cloudflare mode - rejects cf-connecting-ip without Cloudflare headers', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'cloudflare');
  
  const req = createRequest({
    'cf-connecting-ip': '198.51.100.77',
    // No cf-ray or cf-visitor
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, null, 'Should reject cf-connecting-ip without Cloudflare verification');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
});

Deno.test('Cloudflare mode - rejects private IP by default', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'cloudflare');
  
  const req = createRequest({
    'cf-connecting-ip': '192.168.1.100',
    'cf-ray': '1234567890-SJC',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, null, 'Should reject private IP when ALLOW_PRIVATE_IPS not set');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
});

Deno.test('Cloudflare mode - accepts private IP when allowed', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'cloudflare');
  Deno.env.set('ALLOW_PRIVATE_IPS', 'true');
  
  const req = createRequest({
    'cf-connecting-ip': '192.168.1.100',
    'cf-ray': '1234567890-SJC',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, '192.168.1.100', 'Should accept private IP when explicitly allowed');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('ALLOW_PRIVATE_IPS');
});

// Test: XFF mode - trusted hops extraction
Deno.test('XFF mode - extracts correct IP with TRUSTED_HOPS=1', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'xff');
  Deno.env.set('TRUSTED_HOPS', '1');
  
  const req = createRequest({
    'x-forwarded-for': '198.51.100.1, 203.0.113.2, 192.0.2.3',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, '203.0.113.2', 'Should extract second-to-last IP with 1 trusted hop');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_HOPS');
});

Deno.test('XFF mode - extracts first IP with TRUSTED_HOPS=0', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'xff');
  Deno.env.set('TRUSTED_HOPS', '0');
  
  const req = createRequest({
    'x-forwarded-for': '198.51.100.1, 203.0.113.2, 192.0.2.3',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, '192.0.2.3', 'Should extract last IP with 0 trusted hops');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_HOPS');
});

Deno.test('XFF mode - returns null when TRUSTED_HOPS exceeds chain length', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'xff');
  Deno.env.set('TRUSTED_HOPS', '5');
  
  const req = createRequest({
    'x-forwarded-for': '198.51.100.1, 203.0.113.2',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, null, 'Should return null when trusted hops exceeds available IPs');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_HOPS');
});

Deno.test('XFF mode - filters invalid IPs from chain', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'xff');
  Deno.env.set('TRUSTED_HOPS', '1');
  
  const req = createRequest({
    'x-forwarded-for': '198.51.100.1, invalid-ip, 203.0.113.2, 192.0.2.3',
  });
  
  const ip = getClientIp(req);
  // Valid IPs: [198.51.100.1, 203.0.113.2, 192.0.2.3]
  // With TRUSTED_HOPS=1: index = 3 - 1 - 1 = 1 → 203.0.113.2
  assertEquals(ip, '203.0.113.2', 'Should filter out invalid IPs and extract correctly');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_HOPS');
});

Deno.test('XFF mode - rejects private IPs by default', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'xff');
  Deno.env.set('TRUSTED_HOPS', '0');
  
  const req = createRequest({
    'x-forwarded-for': '10.0.0.5',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, null, 'Should reject private IP in XFF mode');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_HOPS');
});

// Test: IP validation
Deno.test('Validation - rejects invalid IPv4', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'xff');
  Deno.env.set('TRUSTED_HOPS', '0');
  
  const req = createRequest({
    'x-forwarded-for': '999.999.999.999',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, null, 'Should reject invalid IPv4 address');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_HOPS');
});

Deno.test('Validation - rejects malformed input', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'xff');
  Deno.env.set('TRUSTED_HOPS', '0');
  
  const req = createRequest({
    'x-forwarded-for': 'not-an-ip',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, null, 'Should reject malformed IP string');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_HOPS');
});

Deno.test('Validation - accepts valid IPv6', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'xff');
  Deno.env.set('TRUSTED_HOPS', '0');
  
  const req = createRequest({
    'x-forwarded-for': '2001:db8::1',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, '2001:db8::1', 'Should accept valid IPv6 address');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_HOPS');
});

Deno.test('Validation - rejects IPv6 loopback', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'xff');
  Deno.env.set('TRUSTED_HOPS', '0');
  
  const req = createRequest({
    'x-forwarded-for': '::1',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, null, 'Should reject IPv6 loopback');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_HOPS');
});

// Test: Edge cases
Deno.test('Edge case - empty header returns null', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'xff');
  
  const req = createRequest({
    'x-forwarded-for': '',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, null, 'Should return null for empty header');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
});

Deno.test('Edge case - missing header returns null', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'xff');
  
  const req = createRequest({});
  
  const ip = getClientIp(req);
  assertEquals(ip, null, 'Should return null when header is missing');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
});

Deno.test('Edge case - whitespace trimmed correctly', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'xff');
  Deno.env.set('TRUSTED_HOPS', '0');
  
  const req = createRequest({
    'x-forwarded-for': '  198.51.100.1  ,  203.0.113.2  ',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, '203.0.113.2', 'Should trim whitespace from IPs');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_HOPS');
});

// Test: Reserved IP ranges
Deno.test('Reserved IPs - rejects loopback 127.0.0.1', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'xff');
  Deno.env.set('TRUSTED_HOPS', '0');
  
  const req = createRequest({
    'x-forwarded-for': '127.0.0.1',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, null, 'Should reject loopback address');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_HOPS');
});

Deno.test('Reserved IPs - rejects link-local 169.254.x.x', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'xff');
  Deno.env.set('TRUSTED_HOPS', '0');
  
  const req = createRequest({
    'x-forwarded-for': '169.254.1.1',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, null, 'Should reject link-local address');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_HOPS');
});

Deno.test('Reserved IPs - rejects multicast 224.x.x.x', () => {
  Deno.env.set('TRUSTED_PROXY_MODE', 'xff');
  Deno.env.set('TRUSTED_HOPS', '0');
  
  const req = createRequest({
    'x-forwarded-for': '224.0.0.1',
  });
  
  const ip = getClientIp(req);
  assertEquals(ip, null, 'Should reject multicast address');
  
  Deno.env.delete('TRUSTED_PROXY_MODE');
  Deno.env.delete('TRUSTED_HOPS');
});
