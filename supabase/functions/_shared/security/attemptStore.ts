/**
 * Storage backend interface for rate limiting attempt tracking
 * Supports both in-memory (for tests/local) and PostgreSQL (production)
 */

/**
 * Error thrown when rate limit storage backend is unavailable
 * This causes fail-closed behavior - blocking requests rather than allowing unlimited attempts
 */
export class RateLimitBackendUnavailable extends Error {
  public readonly operation: string;
  public override readonly cause?: any;
  
  constructor(message: string, operation: string, cause?: any) {
    super(message);
    this.name = 'RateLimitBackendUnavailable';
    this.operation = operation;
    this.cause = cause;
  }
}

export interface AttemptStorage {
  incrementCounter(scope: string, key: string, windowSec: number): Promise<number>;
  getCounter(scope: string, key: string, windowSec: number): Promise<number>;
  setLock(scope: string, key: string, untilEpochMs: number): Promise<void>;
  getLock(scope: string, key: string): Promise<number | null>;
  reset(scope: string, key: string): Promise<void>;
}

interface MemoryEntry {
  value: number;
  expiresAt: number;
}

interface MemoryLockEntry {
  untilEpochMs: number;
}

/**
 * In-memory storage using globalThis for persistence across function calls
 * Suitable for testing and low-traffic scenarios
 */
export class MemoryStore implements AttemptStorage {
  private getStore(): Map<string, MemoryEntry> {
    if (!(globalThis as any).__rateLimitStore) {
      (globalThis as any).__rateLimitStore = new Map<string, MemoryEntry>();
    }
    return (globalThis as any).__rateLimitStore;
  }

  private getLockStore(): Map<string, MemoryLockEntry> {
    if (!(globalThis as any).__rateLimitLocks) {
      (globalThis as any).__rateLimitLocks = new Map<string, MemoryLockEntry>();
    }
    return (globalThis as any).__rateLimitLocks;
  }

  private makeKey(scope: string, key: string, windowSec: number): string {
    return `${scope}:${key}:w${windowSec}`;
  }

  private makeLockKey(scope: string, key: string): string {
    return `${scope}:${key}:lock`;
  }

  async incrementCounter(scope: string, key: string, windowSec: number): Promise<number> {
    const store = this.getStore();
    const storeKey = this.makeKey(scope, key, windowSec);
    const now = Date.now();
    const expiresAt = now + windowSec * 1000;

    const entry = store.get(storeKey);
    if (entry && entry.expiresAt > now) {
      entry.value += 1;
      entry.expiresAt = expiresAt; // refresh TTL
      return entry.value;
    }

    // New or expired entry
    store.set(storeKey, { value: 1, expiresAt });
    return 1;
  }

  async getCounter(scope: string, key: string, windowSec: number): Promise<number> {
    const store = this.getStore();
    const storeKey = this.makeKey(scope, key, windowSec);
    const now = Date.now();

    const entry = store.get(storeKey);
    if (entry && entry.expiresAt > now) {
      return entry.value;
    }

    return 0;
  }

  async setLock(scope: string, key: string, untilEpochMs: number): Promise<void> {
    const lockStore = this.getLockStore();
    const lockKey = this.makeLockKey(scope, key);
    lockStore.set(lockKey, { untilEpochMs });
  }

  async getLock(scope: string, key: string): Promise<number | null> {
    const lockStore = this.getLockStore();
    const lockKey = this.makeLockKey(scope, key);
    const now = Date.now();

    const entry = lockStore.get(lockKey);
    if (entry && entry.untilEpochMs > now) {
      return entry.untilEpochMs;
    }

    return null;
  }

  async reset(scope: string, key: string): Promise<void> {
    const store = this.getStore();
    const lockStore = this.getLockStore();
    
    // Remove all counter windows for this scope:key
    const prefix = `${scope}:${key}:w`;
    for (const storeKey of store.keys()) {
      if (storeKey.startsWith(prefix)) {
        store.delete(storeKey);
      }
    }

    // Remove lock
    const lockKey = this.makeLockKey(scope, key);
    lockStore.delete(lockKey);
  }
}

/**
 * PostgreSQL-backed storage for production use
 * Uses auth_attempts table with upsert logic
 */
export class PostgresStore implements AttemptStorage {
  constructor(private supabaseClient: any) {}

  async incrementCounter(scope: string, key: string, windowSec: number): Promise<number> {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + windowSec * 1000);

    // Upsert: increment count if exists and not expired, else create new
    const { data, error } = await this.supabaseClient
      .rpc('increment_auth_attempt', {
        p_scope: scope,
        p_key: key,
        p_window_seconds: windowSec,
        p_expires_at: expiresAt.toISOString(),
      });

    if (error) {
      console.error('SECURITY: Rate limit backend error on incrementCounter', {
        scope,
        keyPrefix: key.slice(0, 8),
        error: error.message,
      });
      // FAIL CLOSED: Throw error to block request rather than allow unlimited attempts
      throw new RateLimitBackendUnavailable(
        'Rate limit storage unavailable during increment',
        'incrementCounter',
        error
      );
    }

    if (data === null || data === undefined) {
      console.error('SECURITY: Rate limit backend returned no data on incrementCounter', {
        scope,
        keyPrefix: key.slice(0, 8),
      });
      throw new RateLimitBackendUnavailable(
        'Rate limit storage returned no data during increment',
        'incrementCounter'
      );
    }

    return data;
  }

  async getCounter(scope: string, key: string, windowSec: number): Promise<number> {
    const now = new Date().toISOString();

    const { data, error } = await this.supabaseClient
      .from('auth_attempts')
      .select('count')
      .eq('scope', scope)
      .eq('key', key)
      .eq('window_seconds', windowSec)
      .gte('expires_at', now)
      .single();

    if (error) {
      // PGRST116 is "not found" which is acceptable (means no attempts yet)
      if (error.code === 'PGRST116') {
        return 0;
      }
      
      console.error('SECURITY: Rate limit backend error on getCounter', {
        scope,
        keyPrefix: key.slice(0, 8),
        error: error.message,
        code: error.code,
      });
      // FAIL CLOSED: Throw error to block request rather than allow unlimited attempts
      throw new RateLimitBackendUnavailable(
        'Rate limit storage unavailable during counter check',
        'getCounter',
        error
      );
    }

    if (!data) {
      // No data but no error means no attempts yet (legitimate 0)
      return 0;
    }

    return data.count || 0;
  }

  async setLock(scope: string, key: string, untilEpochMs: number): Promise<void> {
    const lockUntil = new Date(untilEpochMs).toISOString();

    const { error } = await this.supabaseClient
      .from('auth_attempts')
      .upsert({
        scope,
        key,
        window_seconds: 0, // 0 indicates lock entry
        lock_until: lockUntil,
        count: 0,
        updated_at: new Date().toISOString(),
      }, {
        onConflict: 'scope,key,window_seconds',
      });

    if (error) {
      console.error('SECURITY: Rate limit backend error on setLock', {
        scope,
        keyPrefix: key.slice(0, 8),
        error: error.message,
      });
      // FAIL CLOSED: Throw error to ensure lockout is recorded
      throw new RateLimitBackendUnavailable(
        'Rate limit storage unavailable during lock set',
        'setLock',
        error
      );
    }
  }

  async getLock(scope: string, key: string): Promise<number | null> {
    const now = new Date().toISOString();

    const { data, error } = await this.supabaseClient
      .from('auth_attempts')
      .select('lock_until')
      .eq('scope', scope)
      .eq('key', key)
      .eq('window_seconds', 0)
      .gte('lock_until', now)
      .single();

    if (error) {
      // PGRST116 is "not found" which is acceptable (means no lock)
      if (error.code === 'PGRST116') {
        return null;
      }
      
      console.error('SECURITY: Rate limit backend error on getLock', {
        scope,
        keyPrefix: key.slice(0, 8),
        error: error.message,
        code: error.code,
      });
      // FAIL CLOSED: Throw error - treat as if account is locked
      throw new RateLimitBackendUnavailable(
        'Rate limit storage unavailable during lock check',
        'getLock',
        error
      );
    }

    if (!data || !data.lock_until) {
      return null;
    }

    return new Date(data.lock_until).getTime();
  }

  async reset(scope: string, key: string): Promise<void> {
    await this.supabaseClient
      .from('auth_attempts')
      .delete()
      .eq('scope', scope)
      .eq('key', key);
  }
}

/**
 * Factory function to create storage based on environment
 * SECURITY: Prevents silent in-memory fallback in production
 */
export function createAttemptStorage(supabaseClient?: any): AttemptStorage {
  const backend = Deno.env.get('RATE_LIMIT_BACKEND') || 'memory';
  const env = Deno.env.get('DENO_ENV') || Deno.env.get('ENV') || 'development';
  const allowMemoryBackend = Deno.env.get('ALLOW_MEMORY_RATE_LIMIT') === 'true';
  
  const isProduction = env === 'production';
  
  if (backend === 'postgres') {
    if (!supabaseClient) {
      console.error('SECURITY: PostgreSQL rate limit backend requested but no client provided');
      throw new RateLimitBackendUnavailable(
        'Rate limit backend misconfigured: postgres requested but no client available',
        'createAttemptStorage'
      );
    }
    console.log('Rate limiter: Using PostgreSQL backend');
    return new PostgresStore(supabaseClient);
  }
  
  if (backend === 'memory') {
    if (isProduction && !allowMemoryBackend) {
      console.error('SECURITY: Memory rate limit backend not allowed in production environment');
      throw new RateLimitBackendUnavailable(
        'Rate limit backend misconfigured: memory backend not allowed in production',
        'createAttemptStorage'
      );
    }
    console.warn('Rate limiter: Using in-memory backend (not recommended for production)', {
      env,
      explicit: allowMemoryBackend,
    });
    return new MemoryStore();
  }
  
  console.error('SECURITY: Unknown rate limit backend specified', { backend });
  throw new RateLimitBackendUnavailable(
    `Rate limit backend misconfigured: unknown backend '${backend}'`,
    'createAttemptStorage'
  );
}
