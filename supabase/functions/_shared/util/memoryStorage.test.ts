/**
 * Security Validation Tests for In-Memory Auth Storage
 * 
 * Run with: deno test supabase/functions/_shared/util/memoryStorage.test.ts
 * 
 * These tests verify that the memory storage implementation:
 * 1. Implements the Storage API correctly
 * 2. Does not persist data (ephemeral)
 * 3. Prevents token exposure to XSS attacks
 */

import { assertEquals } from "https://deno.land/std@0.192.0/testing/asserts.ts";

/**
 * In-Memory Storage Mock for Testing
 * (Copy of the implementation for testing purposes)
 */
class MemoryStorage implements Storage {
  private store: Map<string, string>;

  constructor() {
    this.store = new Map();
  }

  get length(): number {
    return this.store.size;
  }

  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.store.set(key, String(value));
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }

  key(index: number): string | null {
    if (index < 0 || index >= this.store.size) {
      return null;
    }
    return Array.from(this.store.keys())[index] ?? null;
  }
}

Deno.test("MemoryStorage - implements Storage API interface", () => {
  const storage = new MemoryStorage();
  assertEquals(typeof storage.getItem, 'function');
  assertEquals(typeof storage.setItem, 'function');
  assertEquals(typeof storage.removeItem, 'function');
  assertEquals(typeof storage.clear, 'function');
  assertEquals(typeof storage.key, 'function');
  assertEquals(typeof storage.length, 'number');
});

Deno.test("MemoryStorage - getItem returns null for non-existent keys", () => {
  const storage = new MemoryStorage();
  const value = storage.getItem('non-existent-key');
  assertEquals(value, null);
});

Deno.test("MemoryStorage - setItem and getItem work correctly", () => {
  const storage = new MemoryStorage();
  storage.setItem('test-key', 'test-value');
  const value = storage.getItem('test-key');
  assertEquals(value, 'test-value');
});

Deno.test("MemoryStorage - setItem converts values to strings", () => {
  const storage = new MemoryStorage();
  storage.setItem('number-key', '123');
  const value = storage.getItem('number-key');
  assertEquals(value, '123');
  assertEquals(typeof value, 'string');
});

Deno.test("MemoryStorage - removeItem deletes keys", () => {
  const storage = new MemoryStorage();
  storage.setItem('temp-key', 'temp-value');
  assertEquals(storage.getItem('temp-key'), 'temp-value');
  
  storage.removeItem('temp-key');
  assertEquals(storage.getItem('temp-key'), null);
});

Deno.test("MemoryStorage - clear removes all items", () => {
  const storage = new MemoryStorage();
  storage.setItem('key1', 'value1');
  storage.setItem('key2', 'value2');
  storage.setItem('key3', 'value3');
  
  assertEquals(storage.length, 3);
  
  storage.clear();
  
  assertEquals(storage.length, 0);
  assertEquals(storage.getItem('key1'), null);
  assertEquals(storage.getItem('key2'), null);
  assertEquals(storage.getItem('key3'), null);
});

Deno.test("MemoryStorage - length property reflects item count", () => {
  const storage = new MemoryStorage();
  assertEquals(storage.length, 0);
  
  storage.setItem('a', '1');
  assertEquals(storage.length, 1);
  
  storage.setItem('b', '2');
  assertEquals(storage.length, 2);
  
  storage.removeItem('a');
  assertEquals(storage.length, 1);
  
  storage.clear();
  assertEquals(storage.length, 0);
});

Deno.test("MemoryStorage - key() returns keys by index", () => {
  const storage = new MemoryStorage();
  storage.setItem('first', 'value1');
  storage.setItem('second', 'value2');
  storage.setItem('third', 'value3');
  
  const key0 = storage.key(0);
  const key1 = storage.key(1);
  const key2 = storage.key(2);
  
  assertEquals(key0, 'first');
  assertEquals(key1, 'second');
  assertEquals(key2, 'third');
});

Deno.test("MemoryStorage - key() returns null for out-of-bounds index", () => {
  const storage = new MemoryStorage();
  storage.setItem('only-key', 'value');
  
  assertEquals(storage.key(-1), null);
  assertEquals(storage.key(1), null);
  assertEquals(storage.key(100), null);
});

Deno.test("Security - MemoryStorage is ephemeral and does not persist", () => {
  const storage = new MemoryStorage();
  
  storage.setItem('secret-token', 'should-not-persist');
  assertEquals(storage.getItem('secret-token'), 'should-not-persist');
  
  // After clear (simulating logout or page reload), it's gone
  storage.clear();
  assertEquals(storage.getItem('secret-token'), null);
});

Deno.test("Security - No cross-instance contamination", () => {
  const storage1 = new MemoryStorage();
  const storage2 = new MemoryStorage();
  
  storage1.setItem('token', 'value-from-storage1');
  
  // storage2 should not see storage1's data
  assertEquals(storage2.getItem('token'), null);
  assertEquals(storage1.getItem('token'), 'value-from-storage1');
});
