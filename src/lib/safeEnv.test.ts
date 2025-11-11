/**
 * Tests for Safe Environment Validation
 * 
 * SECURITY NOTE: All tokens in this file are synthetic test fixtures.
 * They are NOT real credentials and have been crafted for testing purposes only.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock import.meta.env
const mockEnv: Record<string, string> = {};

vi.stubGlobal('import', {
  meta: {
    get env() {
      return {
        ...mockEnv,
        DEV: mockEnv.DEV === 'true',
      };
    },
  },
});

// Helper to create synthetic JWT tokens for testing
function createTestToken(role: string): string {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = btoa(JSON.stringify({ 
    role, 
    iss: 'test',
    iat: 1234567890,
    exp: 9999999999,
  }));
  const signature = 'test_signature_not_verified_client_side';
  return `${header}.${payload}.${signature}`;
}

describe('safeEnv - Runtime Credential Validation', () => {
  beforeEach(() => {
    // Clear mocked env before each test
    Object.keys(mockEnv).forEach(key => delete mockEnv[key]);
    mockEnv.DEV = 'true';
    vi.resetModules();
  });

  describe('Security Tests - Service Role Key Detection', () => {
    it('should reject service_role token and throw clear error in development', async () => {
      mockEnv.VITE_SUPABASE_URL = 'https://testproject.supabase.co';
      mockEnv.VITE_SUPABASE_PROJECT_ID = 'testproject';
      mockEnv.VITE_SUPABASE_PUBLISHABLE_KEY = createTestToken('service_role');

      const { getClientEnv } = await import('./safeEnv');
      
      expect(() => getClientEnv()).toThrow(/service_role/i);
      expect(() => getClientEnv()).toThrow(/NEVER use service_role/i);
    });

    it('should reject service_role token in production with generic error', async () => {
      mockEnv.DEV = 'false';
      mockEnv.VITE_SUPABASE_URL = 'https://testproject.supabase.co';
      mockEnv.VITE_SUPABASE_PROJECT_ID = 'testproject';
      mockEnv.VITE_SUPABASE_PUBLISHABLE_KEY = createTestToken('service_role');

      const { getClientEnv } = await import('./safeEnv');
      
      expect(() => getClientEnv()).toThrow('Application configuration error');
      expect(() => getClientEnv()).not.toThrow(/service_role/i);
    });

    it('should reject authenticated token (non-anon role)', async () => {
      mockEnv.VITE_SUPABASE_URL = 'https://testproject.supabase.co';
      mockEnv.VITE_SUPABASE_PROJECT_ID = 'testproject';
      mockEnv.VITE_SUPABASE_PUBLISHABLE_KEY = createTestToken('authenticated');

      const { getClientEnv } = await import('./safeEnv');
      
      expect(() => getClientEnv()).toThrow(/Dangerous key detected/i);
    });
  });

  describe('Functionality Tests - Valid Anon Key', () => {
    it('should accept valid anon token and return environment', async () => {
      const validAnonKey = createTestToken('anon');
      mockEnv.VITE_SUPABASE_URL = 'https://validproject.supabase.co';
      mockEnv.VITE_SUPABASE_PROJECT_ID = 'validproject';
      mockEnv.VITE_SUPABASE_PUBLISHABLE_KEY = validAnonKey;

      const { getClientEnv } = await import('./safeEnv');
      
      const result = getClientEnv();
      
      expect(result).toEqual({
        url: 'https://validproject.supabase.co',
        anonKey: validAnonKey,
        projectId: 'validproject',
      });
    });

    it('should not throw when initializeEnv is called with valid config', async () => {
      mockEnv.VITE_SUPABASE_URL = 'https://validproject.supabase.co';
      mockEnv.VITE_SUPABASE_PROJECT_ID = 'validproject';
      mockEnv.VITE_SUPABASE_PUBLISHABLE_KEY = createTestToken('anon');

      const { initializeEnv } = await import('./safeEnv');
      
      expect(() => initializeEnv()).not.toThrow();
    });
  });

  describe('Edge Cases - Missing or Invalid Configuration', () => {
    it('should reject missing VITE_SUPABASE_URL', async () => {
      mockEnv.VITE_SUPABASE_PROJECT_ID = 'testproject';
      mockEnv.VITE_SUPABASE_PUBLISHABLE_KEY = createTestToken('anon');
      // URL is missing

      const { getClientEnv } = await import('./safeEnv');
      
      expect(() => getClientEnv()).toThrow(/VITE_SUPABASE_URL is not configured/i);
    });

    it('should reject placeholder URL', async () => {
      mockEnv.VITE_SUPABASE_URL = 'https://<your-project-ref>.supabase.co';
      mockEnv.VITE_SUPABASE_PROJECT_ID = 'testproject';
      mockEnv.VITE_SUPABASE_PUBLISHABLE_KEY = createTestToken('anon');

      const { getClientEnv } = await import('./safeEnv');
      
      expect(() => getClientEnv()).toThrow(/VITE_SUPABASE_URL is not configured/i);
    });

    it('should reject missing VITE_SUPABASE_PUBLISHABLE_KEY', async () => {
      mockEnv.VITE_SUPABASE_URL = 'https://testproject.supabase.co';
      mockEnv.VITE_SUPABASE_PROJECT_ID = 'testproject';
      // Key is missing

      const { getClientEnv } = await import('./safeEnv');
      
      expect(() => getClientEnv()).toThrow(/VITE_SUPABASE_PUBLISHABLE_KEY is not configured/i);
    });

    it('should reject placeholder publishable key', async () => {
      mockEnv.VITE_SUPABASE_URL = 'https://testproject.supabase.co';
      mockEnv.VITE_SUPABASE_PROJECT_ID = 'testproject';
      mockEnv.VITE_SUPABASE_PUBLISHABLE_KEY = '<your-anon-key>';

      const { getClientEnv } = await import('./safeEnv');
      
      expect(() => getClientEnv()).toThrow(/VITE_SUPABASE_PUBLISHABLE_KEY is not configured/i);
    });

    it('should reject malformed JWT (no dots)', async () => {
      mockEnv.VITE_SUPABASE_URL = 'https://testproject.supabase.co';
      mockEnv.VITE_SUPABASE_PROJECT_ID = 'testproject';
      mockEnv.VITE_SUPABASE_PUBLISHABLE_KEY = 'not-a-valid-jwt-token';

      const { getClientEnv } = await import('./safeEnv');
      
      expect(() => getClientEnv()).toThrow(/Invalid Supabase key format/i);
    });

    it('should reject JWT with invalid base64 payload', async () => {
      mockEnv.VITE_SUPABASE_URL = 'https://testproject.supabase.co';
      mockEnv.VITE_SUPABASE_PROJECT_ID = 'testproject';
      mockEnv.VITE_SUPABASE_PUBLISHABLE_KEY = 'header.invalid!!!base64.signature';

      const { getClientEnv } = await import('./safeEnv');
      
      expect(() => getClientEnv()).toThrow(/Invalid Supabase key format/i);
    });

    it('should reject empty project ID', async () => {
      mockEnv.VITE_SUPABASE_URL = 'https://testproject.supabase.co';
      mockEnv.VITE_SUPABASE_PROJECT_ID = '';
      mockEnv.VITE_SUPABASE_PUBLISHABLE_KEY = createTestToken('anon');

      const { getClientEnv } = await import('./safeEnv');
      
      expect(() => getClientEnv()).toThrow(/VITE_SUPABASE_PROJECT_ID is not configured/i);
    });
  });

  describe('Production Mode Behavior', () => {
    it('should not expose sensitive details in production error messages', async () => {
      mockEnv.DEV = 'false';
      mockEnv.VITE_SUPABASE_URL = 'https://testproject.supabase.co';
      mockEnv.VITE_SUPABASE_PROJECT_ID = 'testproject';
      mockEnv.VITE_SUPABASE_PUBLISHABLE_KEY = createTestToken('service_role');

      const { getClientEnv } = await import('./safeEnv');
      
      try {
        getClientEnv();
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect((error as Error).message).toBe('Application configuration error');
        expect((error as Error).message).not.toContain('service_role');
        expect((error as Error).message).not.toContain('JWT');
      }
    });
  });
});
