/**
 * Rate limiter with per-IP and per-identifier throttling
 * Implements exponential backoff and temporary lockout
 */

import { AttemptStorage, createAttemptStorage } from './attemptStore.ts';

// Throttling thresholds
const IP_LIMIT_PER_MINUTE = 10;
const IP_LIMIT_PER_HOUR = 50;
const IP_WINDOW_60S = 60;
const IP_WINDOW_3600S = 3600;

const ID_SOFT_LIMIT = 5; // Start backoff after this many failures
const ID_LOCKOUT_LIMIT = 10; // Hard lockout after this many consecutive failures
const ID_WINDOW_60S = 60;
const ID_WINDOW_900S = 900; // 15 minutes for lockout tracking

const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes
const MAX_BACKOFF_SECONDS = 900; // 15 minutes max backoff

export interface RateLimitVerdict {
  allowed: boolean;
  reason?: 'ip' | 'identifier' | 'lockout';
  retryAfterSeconds?: number;
}

export class RateLimiter {
  constructor(private storage: AttemptStorage) {}

  /**
   * Check if request is allowed and consume a slot if it is
   * @param ip Client IP address (null if untrusted)
   * @param identifierKey Normalized identifier for the user
   */
  async checkAndConsume(ip: string | null, identifierKey: string): Promise<RateLimitVerdict> {
    // Check lockout first
    const lockUntil = await this.storage.getLock('id', identifierKey);
    if (lockUntil) {
      const retryAfterSeconds = Math.ceil((lockUntil - Date.now()) / 1000);
      console.log('Rate limit: lockout active', { 
        idPrefix: identifierKey.slice(0, 8), 
        retryAfter: retryAfterSeconds 
      });
      return {
        allowed: false,
        reason: 'lockout',
        retryAfterSeconds: Math.max(1, retryAfterSeconds),
      };
    }

    // Check per-IP limits (only if IP is trusted)
    if (ip !== null) {
      const ipCount60s = await this.storage.getCounter('ip', ip, IP_WINDOW_60S);
      if (ipCount60s >= IP_LIMIT_PER_MINUTE) {
        console.log('Rate limit: IP throttled (60s window)', { ip, count: ipCount60s });
        return {
          allowed: false,
          reason: 'ip',
          retryAfterSeconds: 60,
        };
      }

      const ipCount3600s = await this.storage.getCounter('ip', ip, IP_WINDOW_3600S);
      if (ipCount3600s >= IP_LIMIT_PER_HOUR) {
        console.log('Rate limit: IP throttled (3600s window)', { ip, count: ipCount3600s });
        return {
          allowed: false,
          reason: 'ip',
          retryAfterSeconds: 600, // 10 minutes
        };
      }
    }

    // Check per-identifier soft limit with exponential backoff
    const idCount60s = await this.storage.getCounter('id', identifierKey, ID_WINDOW_60S);
    if (idCount60s >= ID_SOFT_LIMIT) {
      const backoffSeconds = Math.min(
        Math.pow(2, idCount60s - ID_SOFT_LIMIT) * 5,
        MAX_BACKOFF_SECONDS
      );
      console.log('Rate limit: identifier throttled with backoff', {
        idPrefix: identifierKey.slice(0, 8),
        count: idCount60s,
        backoff: backoffSeconds,
      });
      return {
        allowed: false,
        reason: 'identifier',
        retryAfterSeconds: Math.ceil(backoffSeconds),
      };
    }

    // Consume slots for both IP (if available) and identifier
    if (ip !== null) {
      await this.storage.incrementCounter('ip', ip, IP_WINDOW_60S);
      await this.storage.incrementCounter('ip', ip, IP_WINDOW_3600S);
    }
    await this.storage.incrementCounter('id', identifierKey, ID_WINDOW_60S);

    return { allowed: true };
  }

  /**
   * Record a failed authentication attempt
   * Increments failure counters and applies lockout if threshold exceeded
   * @param ip Client IP address (null if untrusted)
   * @param identifierKey Normalized identifier for the user
   */
  async recordFailure(ip: string | null, identifierKey: string): Promise<void> {
    // Track consecutive failures for lockout
    const consecutiveFailures = await this.storage.incrementCounter(
      'id',
      identifierKey,
      ID_WINDOW_900S
    );

    console.log('Rate limit: recording failure', {
      ip,
      idPrefix: identifierKey.slice(0, 8),
      consecutiveFailures,
    });

    // Apply lockout if threshold exceeded
    if (consecutiveFailures >= ID_LOCKOUT_LIMIT) {
      const lockUntil = Date.now() + LOCKOUT_DURATION_MS;
      await this.storage.setLock('id', identifierKey, lockUntil);
      console.log('Rate limit: lockout applied', {
        idPrefix: identifierKey.slice(0, 8),
        lockDurationMinutes: 15,
      });
    }
  }

  /**
   * Record a successful authentication
   * Resets all counters and clears lockout for the identifier
   */
  async recordSuccess(identifierKey: string): Promise<void> {
    console.log('Rate limit: recording success, resetting counters', {
      idPrefix: identifierKey.slice(0, 8),
    });
    await this.storage.reset('id', identifierKey);
  }
}

/**
 * Create a rate limiter instance with storage backend
 */
export function createRateLimiter(supabaseClient?: any): RateLimiter {
  const storage = createAttemptStorage(supabaseClient);
  return new RateLimiter(storage);
}
