/**
 * In-Memory Storage Adapter for Supabase Auth
 * 
 * Security: Replaces localStorage to prevent auth token exposure to XSS attacks.
 * Trade-off: Sessions will NOT survive page reloads - users must re-authenticate.
 * 
 * This adapter implements the Web Storage API interface but stores data
 * in memory only, eliminating the XSS attack surface of localStorage.
 * 
 * Important: This is a per-tab, ephemeral storage. Tokens are never persisted
 * to disk or shared across tabs.
 */

class MemoryStorage implements Storage {
  private store: Map<string, string>;

  constructor() {
    this.store = new Map();
  }

  get length(): number {
    return this.store.size;
  }

  /**
   * Get an item from memory storage
   * Returns null if the key doesn't exist (matching Storage API)
   */
  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  /**
   * Set an item in memory storage
   * All values are stored as strings (matching Storage API)
   */
  setItem(key: string, value: string): void {
    this.store.set(key, String(value));
  }

  /**
   * Remove an item from memory storage
   */
  removeItem(key: string): void {
    this.store.delete(key);
  }

  /**
   * Clear all items from memory storage
   * Called on logout to ensure no residual auth state
   */
  clear(): void {
    this.store.clear();
  }

  /**
   * Get the key at a specific index
   * Returns null if index is out of bounds (matching Storage API)
   */
  key(index: number): string | null {
    if (index < 0 || index >= this.store.size) {
      return null;
    }
    return Array.from(this.store.keys())[index] ?? null;
  }
}

/**
 * Singleton instance - one storage per tab/window
 * This ensures consistent auth state within a single tab session
 */
export const memoryStorage = new MemoryStorage();
