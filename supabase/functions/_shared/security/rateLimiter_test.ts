/**
 * Unit tests for rate limiter
 */

import { assertEquals } from 'https://deno.land/std@0.168.0/testing/asserts.ts';
import { RateLimiter } from './rateLimiter.ts';
import { MemoryStore } from './attemptStore.ts';

Deno.test('RateLimiter - allows first attempts', async () => {
  const storage = new MemoryStore();
  const limiter = new RateLimiter(storage);

  const verdict = await limiter.checkAndConsume('192.168.1.1', 'hash123');
  assertEquals(verdict.allowed, true);
});

Deno.test('RateLimiter - applies exponential backoff after soft limit', async () => {
  const storage = new MemoryStore();
  const limiter = new RateLimiter(storage);

  const ip = '192.168.1.2';
  const idKey = 'hash456';

  // First 5 attempts should be allowed
  for (let i = 0; i < 5; i++) {
    const verdict = await limiter.checkAndConsume(ip, idKey);
    assertEquals(verdict.allowed, true, `Attempt ${i + 1} should be allowed`);
  }

  // 6th attempt should trigger backoff
  const verdict = await limiter.checkAndConsume(ip, idKey);
  assertEquals(verdict.allowed, false);
  assertEquals(verdict.reason, 'identifier');
  assertEquals((verdict.retryAfterSeconds ?? 0) >= 5, true);
});

Deno.test('RateLimiter - applies lockout after 10 failures', async () => {
  const storage = new MemoryStore();
  const limiter = new RateLimiter(storage);

  const ip = '192.168.1.3';
  const idKey = 'hash789';

  // Simulate 10 consecutive failures
  for (let i = 0; i < 10; i++) {
    await limiter.recordFailure(ip, idKey);
  }

  // Next attempt should be locked out
  const verdict = await limiter.checkAndConsume(ip, idKey);
  assertEquals(verdict.allowed, false);
  assertEquals(verdict.reason, 'lockout');
  assertEquals((verdict.retryAfterSeconds ?? 0) > 0, true);
});

Deno.test('RateLimiter - success resets identifier counters', async () => {
  const storage = new MemoryStore();
  const limiter = new RateLimiter(storage);

  const ip = '192.168.1.4';
  const idKey = 'hashabc';

  // Make some failed attempts
  for (let i = 0; i < 3; i++) {
    await limiter.checkAndConsume(ip, idKey);
    await limiter.recordFailure(ip, idKey);
  }

  // Record success
  await limiter.recordSuccess(idKey);

  // Next attempt should be allowed (counters reset)
  const verdict = await limiter.checkAndConsume(ip, idKey);
  assertEquals(verdict.allowed, true);
});

Deno.test('RateLimiter - enforces per-IP limit', async () => {
  const storage = new MemoryStore();
  const limiter = new RateLimiter(storage);

  const ip = '192.168.1.5';

  // Make 10 attempts with different identifiers
  for (let i = 0; i < 10; i++) {
    const verdict = await limiter.checkAndConsume(ip, `id${i}`);
    assertEquals(verdict.allowed, true, `Attempt ${i + 1} should be allowed`);
  }

  // 11th attempt should be blocked by IP limit
  const verdict = await limiter.checkAndConsume(ip, 'id99');
  assertEquals(verdict.allowed, false);
  assertEquals(verdict.reason, 'ip');
  assertEquals((verdict.retryAfterSeconds ?? 0) > 0, true);
});
