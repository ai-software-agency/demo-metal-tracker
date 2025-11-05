/**
 * Storage backend interface for rate limiting attempt tracking
 * Supports both in-memory (for tests/local) and PostgreSQL (production)
 */

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
      console.error('Error incrementing auth attempt:', error);
      return 0;
    }

    return data || 0;
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

    if (error || !data) {
      return 0;
    }

    return data.count || 0;
  }

  async setLock(scope: string, key: string, untilEpochMs: number): Promise<void> {
    const lockUntil = new Date(untilEpochMs).toISOString();

    await this.supabaseClient
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

    if (error || !data || !data.lock_until) {
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
 */
export function createAttemptStorage(supabaseClient?: any): AttemptStorage {
  const backend = Deno.env.get('RATE_LIMIT_BACKEND') || 'memory';
  
  if (backend === 'postgres' && supabaseClient) {
    return new PostgresStore(supabaseClient);
  }
  
  return new MemoryStore();
}
