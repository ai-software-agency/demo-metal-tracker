import { assertEquals, assertRejects } from 'https://deno.land/std@0.208.0/assert/mod.ts';
import {
  MemoryStore,
  PostgresStore,
  RateLimitBackendUnavailable,
  createAttemptStorage,
} from './attemptStore.ts';

// ============================================================================
// MemoryStore Tests (baseline - should not throw)
// ============================================================================

Deno.test('MemoryStore - incrementCounter works normally', async () => {
  const store = new MemoryStore();
  const count1 = await store.incrementCounter('test', 'key1', 60);
  assertEquals(count1, 1);
  
  const count2 = await store.incrementCounter('test', 'key1', 60);
  assertEquals(count2, 2);
});

Deno.test('MemoryStore - getCounter returns 0 when no entry', async () => {
  const store = new MemoryStore();
  const count = await store.getCounter('test', 'nonexistent', 60);
  assertEquals(count, 0);
});

Deno.test('MemoryStore - lock operations work normally', async () => {
  const store = new MemoryStore();
  
  const lockBefore = await store.getLock('test', 'key1');
  assertEquals(lockBefore, null);
  
  const lockUntil = Date.now() + 5000;
  await store.setLock('test', 'key1', lockUntil);
  
  const lockAfter = await store.getLock('test', 'key1');
  assertEquals(lockAfter, lockUntil);
});

// ============================================================================
// PostgresStore Fail-Closed Tests (Mock error scenarios)
// ============================================================================

function createMockSupabaseClient(scenario: 'error' | 'no_data' | 'success', returnData?: any) {
  return {
    rpc: async (fnName: string, params: any) => {
      if (scenario === 'error') {
        return { data: null, error: { message: 'Connection failed', code: 'PGRST500' } };
      }
      if (scenario === 'no_data') {
        return { data: null, error: null };
      }
      return { data: returnData ?? 1, error: null };
    },
    from: (table: string) => ({
      select: (cols: string) => ({
        eq: (col: string, val: any) => ({
          eq: (col2: string, val2: any) => ({
            eq: (col3: string, val3: any) => ({
              gte: (col4: string, val4: any) => ({
                single: async () => {
                  if (scenario === 'error') {
                    return { data: null, error: { message: 'Query failed', code: 'PGRST500' } };
                  }
                  if (scenario === 'no_data') {
                    return { data: null, error: { code: 'PGRST116', message: 'Not found' } };
                  }
                  return { data: returnData ?? { count: 5 }, error: null };
                },
              }),
            }),
          }),
        }),
      }),
      upsert: (data: any, opts: any) => ({
        then: async (resolve: any) => {
          if (scenario === 'error') {
            resolve({ data: null, error: { message: 'Upsert failed', code: 'PGRST500' } });
          } else {
            resolve({ data: {}, error: null });
          }
        },
      }),
      delete: () => ({
        eq: (col: string, val: any) => ({
          eq: (col2: string, val2: any) => ({
            then: async (resolve: any) => {
              resolve({ data: {}, error: null });
            },
          }),
        }),
      }),
    }),
  };
}

Deno.test('PostgresStore - incrementCounter throws on backend error', async () => {
  const mockClient = createMockSupabaseClient('error');
  const store = new PostgresStore(mockClient);
  
  await assertRejects(
    async () => await store.incrementCounter('test', 'key1', 60),
    RateLimitBackendUnavailable,
    'Rate limit storage unavailable during increment'
  );
});

Deno.test('PostgresStore - incrementCounter throws when no data returned', async () => {
  const mockClient = createMockSupabaseClient('no_data');
  const store = new PostgresStore(mockClient);
  
  await assertRejects(
    async () => await store.incrementCounter('test', 'key1', 60),
    RateLimitBackendUnavailable,
    'Rate limit storage returned no data during increment'
  );
});

Deno.test('PostgresStore - incrementCounter succeeds with valid data', async () => {
  const mockClient = createMockSupabaseClient('success', 3);
  const store = new PostgresStore(mockClient);
  
  const count = await store.incrementCounter('test', 'key1', 60);
  assertEquals(count, 3);
});

Deno.test('PostgresStore - getCounter throws on backend error (non-PGRST116)', async () => {
  const mockClient = createMockSupabaseClient('error');
  const store = new PostgresStore(mockClient);
  
  await assertRejects(
    async () => await store.getCounter('test', 'key1', 60),
    RateLimitBackendUnavailable,
    'Rate limit storage unavailable during counter check'
  );
});

Deno.test('PostgresStore - getCounter returns 0 on PGRST116 (not found)', async () => {
  const mockClient = createMockSupabaseClient('no_data');
  const store = new PostgresStore(mockClient);
  
  const count = await store.getCounter('test', 'key1', 60);
  assertEquals(count, 0);
});

Deno.test('PostgresStore - getCounter returns count from data', async () => {
  const mockClient = createMockSupabaseClient('success', { count: 7 });
  const store = new PostgresStore(mockClient);
  
  const count = await store.getCounter('test', 'key1', 60);
  assertEquals(count, 7);
});

Deno.test('PostgresStore - setLock throws on backend error', async () => {
  const mockClient = createMockSupabaseClient('error');
  const store = new PostgresStore(mockClient);
  
  await assertRejects(
    async () => await store.setLock('test', 'key1', Date.now() + 5000),
    RateLimitBackendUnavailable,
    'Rate limit storage unavailable during lock set'
  );
});

Deno.test('PostgresStore - getLock throws on backend error (non-PGRST116)', async () => {
  const mockClient = createMockSupabaseClient('error');
  const store = new PostgresStore(mockClient);
  
  await assertRejects(
    async () => await store.getLock('test', 'key1'),
    RateLimitBackendUnavailable,
    'Rate limit storage unavailable during lock check'
  );
});

Deno.test('PostgresStore - getLock returns null on PGRST116 (not found)', async () => {
  const mockClient = createMockSupabaseClient('no_data');
  const store = new PostgresStore(mockClient);
  
  const lock = await store.getLock('test', 'key1');
  assertEquals(lock, null);
});

Deno.test('PostgresStore - getLock returns timestamp from data', async () => {
  const lockTime = Date.now() + 10000;
  const mockClient = createMockSupabaseClient('success', { 
    lock_until: new Date(lockTime).toISOString() 
  });
  const store = new PostgresStore(mockClient);
  
  const lock = await store.getLock('test', 'key1');
  assertEquals(typeof lock, 'number');
  assertEquals(Math.abs(lock! - lockTime) < 1000, true); // Allow small time diff
});

// ============================================================================
// Factory Tests (Production Safety)
// ============================================================================

Deno.test('createAttemptStorage - throws when postgres requested without client', () => {
  const originalBackend = Deno.env.get('RATE_LIMIT_BACKEND');
  try {
    Deno.env.set('RATE_LIMIT_BACKEND', 'postgres');
    
    let error: Error | undefined;
    try {
      createAttemptStorage(undefined);
    } catch (e) {
      error = e as Error;
    }
    
    assertEquals(error instanceof RateLimitBackendUnavailable, true);
    if (error) {
      assertEquals(error.message.includes('no client'), true);
    }
  } finally {
    if (originalBackend) {
      Deno.env.set('RATE_LIMIT_BACKEND', originalBackend);
    } else {
      Deno.env.delete('RATE_LIMIT_BACKEND');
    }
  }
});

Deno.test('createAttemptStorage - throws in production with memory backend (no explicit allow)', () => {
  const originalEnv = Deno.env.get('DENO_ENV');
  const originalBackend = Deno.env.get('RATE_LIMIT_BACKEND');
  const originalAllow = Deno.env.get('ALLOW_MEMORY_RATE_LIMIT');
  
  try {
    Deno.env.set('DENO_ENV', 'production');
    Deno.env.set('RATE_LIMIT_BACKEND', 'memory');
    Deno.env.delete('ALLOW_MEMORY_RATE_LIMIT');
    
    let error: Error | undefined;
    try {
      createAttemptStorage();
    } catch (e) {
      error = e as Error;
    }
    
    assertEquals(error instanceof RateLimitBackendUnavailable, true);
    if (error) {
      assertEquals(error.message.includes('not allowed in production'), true);
    }
  } finally {
    if (originalEnv) {
      Deno.env.set('DENO_ENV', originalEnv);
    } else {
      Deno.env.delete('DENO_ENV');
    }
    if (originalBackend) {
      Deno.env.set('RATE_LIMIT_BACKEND', originalBackend);
    } else {
      Deno.env.delete('RATE_LIMIT_BACKEND');
    }
    if (originalAllow) {
      Deno.env.set('ALLOW_MEMORY_RATE_LIMIT', originalAllow);
    } else {
      Deno.env.delete('ALLOW_MEMORY_RATE_LIMIT');
    }
  }
});

Deno.test('createAttemptStorage - allows memory in production with explicit flag', () => {
  const originalEnv = Deno.env.get('DENO_ENV');
  const originalBackend = Deno.env.get('RATE_LIMIT_BACKEND');
  const originalAllow = Deno.env.get('ALLOW_MEMORY_RATE_LIMIT');
  
  try {
    Deno.env.set('DENO_ENV', 'production');
    Deno.env.set('RATE_LIMIT_BACKEND', 'memory');
    Deno.env.set('ALLOW_MEMORY_RATE_LIMIT', 'true');
    
    const store = createAttemptStorage();
    assertEquals(store instanceof MemoryStore, true);
  } finally {
    if (originalEnv) {
      Deno.env.set('DENO_ENV', originalEnv);
    } else {
      Deno.env.delete('DENO_ENV');
    }
    if (originalBackend) {
      Deno.env.set('RATE_LIMIT_BACKEND', originalBackend);
    } else {
      Deno.env.delete('RATE_LIMIT_BACKEND');
    }
    if (originalAllow) {
      Deno.env.set('ALLOW_MEMORY_RATE_LIMIT', originalAllow);
    } else {
      Deno.env.delete('ALLOW_MEMORY_RATE_LIMIT');
    }
  }
});

Deno.test('createAttemptStorage - allows memory in development by default', () => {
  const originalEnv = Deno.env.get('DENO_ENV');
  const originalBackend = Deno.env.get('RATE_LIMIT_BACKEND');
  
  try {
    Deno.env.set('DENO_ENV', 'development');
    Deno.env.set('RATE_LIMIT_BACKEND', 'memory');
    
    const store = createAttemptStorage();
    assertEquals(store instanceof MemoryStore, true);
  } finally {
    if (originalEnv) {
      Deno.env.set('DENO_ENV', originalEnv);
    } else {
      Deno.env.delete('DENO_ENV');
    }
    if (originalBackend) {
      Deno.env.set('RATE_LIMIT_BACKEND', originalBackend);
    } else {
      Deno.env.delete('RATE_LIMIT_BACKEND');
    }
  }
});

Deno.test('createAttemptStorage - throws on unknown backend', () => {
  const originalBackend = Deno.env.get('RATE_LIMIT_BACKEND');
  
  try {
    Deno.env.set('RATE_LIMIT_BACKEND', 'redis');
    
    let error: Error | undefined;
    try {
      createAttemptStorage();
    } catch (e) {
      error = e as Error;
    }
    
    assertEquals(error instanceof RateLimitBackendUnavailable, true);
    if (error) {
      assertEquals(error.message.includes('unknown backend'), true);
    }
  } finally {
    if (originalBackend) {
      Deno.env.set('RATE_LIMIT_BACKEND', originalBackend);
    } else {
      Deno.env.delete('RATE_LIMIT_BACKEND');
    }
  }
});
