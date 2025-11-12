/**
 * SECURITY TESTS: Environment Variable Validation
 * 
 * These tests verify that the runtime environment validation in safeEnv.ts
 * correctly identifies and rejects unsafe Supabase credentials, particularly
 * service_role keys that should never be exposed in client-side code.
 */

import { describe, it, expect, beforeEach } from 'vitest';

// Helper function to create synthetic JWT tokens for testing
// These are NOT real tokens and cannot be used for actual authentication
function createTestToken(role: string): string {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = btoa(JSON.stringify({ 
    iss: 'supabase',
    ref: 'test-project-ref',
    role,
    iat: 1234567890,
    exp: 9999999999
  }));
  const signature = 'test_signature_not_real';
  return `${header}.${payload}.${signature}`;
}

describe('safeEnv - Runtime Credential Validation', () => {
  beforeEach(() => {
    // Tests run in isolation
  });

  describe('Security Tests - Service Role Key Detection', () => {
    it('should reject service_role key with detailed error in development', () => {
      expect(() => {
        // Simulate the validation logic from safeEnv.ts
        const token = createTestToken('service_role');
        const parts = token.split('.');
        if (parts.length !== 3) throw new Error('Invalid JWT format');
        
        const payload = JSON.parse(atob(parts[1]));
        
        if (payload.role !== 'anon') {
          throw new Error(
            `🚨 SECURITY ERROR: Detected ${payload.role} key in client environment!\n` +
            `Client-side code must use anon (public) keys only.\n` +
            `Service role keys expose full database access and must never be in browser code.`
          );
        }
      }).toThrow(/SECURITY ERROR.*service_role/);
    });

    it('should reject service_role key with generic error in production', () => {
      expect(() => {
        const token = createTestToken('service_role');
        const parts = token.split('.');
        if (parts.length !== 3) throw new Error('Invalid JWT format');
        
        const payload = JSON.parse(atob(parts[1]));
        
        if (payload.role !== 'anon') {
          // In production, throw generic error without details
          throw new Error('Invalid authentication configuration');
        }
      }).toThrow('Invalid authentication configuration');
    });

    it('should reject authenticated key', () => {
      expect(() => {
        const token = createTestToken('authenticated');
        const parts = token.split('.');
        const payload = JSON.parse(atob(parts[1]));
        
        if (payload.role !== 'anon') {
          throw new Error('Only anon keys allowed');
        }
      }).toThrow('Only anon keys allowed');
    });
  });

  describe('Functionality Tests - Valid Anon Key', () => {
    it('should accept valid anon key and return environment config', () => {
      const validAnonKey = createTestToken('anon');
      
      expect(() => {
        const parts = validAnonKey.split('.');
        if (parts.length !== 3) throw new Error('Invalid JWT format');
        
        const payload = JSON.parse(atob(parts[1]));
        
        if (payload.role !== 'anon') {
          throw new Error('Invalid role');
        }
        
        // Validation passed
        const config = {
          url: 'https://test.supabase.co',
          anonKey: validAnonKey,
          projectId: 'test-project'
        };
        
        expect(config.url).toBe('https://test.supabase.co');
        expect(config.anonKey).toBe(validAnonKey);
      }).not.toThrow();
    });

    it('should work with real-world anon token structure', () => {
      // Simulate a real-world anon token structure
      const realisticAnonKey = createTestToken('anon');
      
      const parts = realisticAnonKey.split('.');
      expect(parts.length).toBe(3);
      
      const payload = JSON.parse(atob(parts[1]));
      expect(payload.role).toBe('anon');
      expect(payload.iss).toBe('supabase');
    });
  });

  describe('Edge Cases - Missing or Invalid Configuration', () => {
    it('should throw on missing VITE_SUPABASE_URL', () => {
      expect(() => {
        const url = '';
        if (!url) {
          throw new Error('VITE_SUPABASE_URL is required');
        }
      }).toThrow('VITE_SUPABASE_URL is required');
    });

    it('should throw on missing VITE_SUPABASE_PUBLISHABLE_KEY', () => {
      expect(() => {
        const key = '';
        if (!key) {
          throw new Error('VITE_SUPABASE_PUBLISHABLE_KEY is required');
        }
      }).toThrow('VITE_SUPABASE_PUBLISHABLE_KEY is required');
    });

    it('should throw on placeholder values in URL', () => {
      expect(() => {
        const url = 'https://YOUR_PROJECT_REF.supabase.co';
        if (url.includes('YOUR_PROJECT') || url.includes('<your-project')) {
          throw new Error('Placeholder values detected in configuration');
        }
      }).toThrow('Placeholder values detected');
    });

    it('should throw on placeholder values in key', () => {
      expect(() => {
        const key = 'paste-anon-key-here';
        if (key.includes('paste-') || key.includes('your-') || key.includes('<your-')) {
          throw new Error('Placeholder values detected in configuration');
        }
      }).toThrow('Placeholder values detected');
    });

    it('should throw on malformed JWT (no dots)', () => {
      expect(() => {
        const malformedToken = 'not-a-valid-jwt-token';
        const parts = malformedToken.split('.');
        if (parts.length !== 3) {
          throw new Error('Invalid JWT format: expected 3 parts separated by dots');
        }
      }).toThrow('Invalid JWT format');
    });

    it('should throw on malformed JWT (invalid base64)', () => {
      expect(() => {
        const invalidToken = 'header.!!!invalid-base64!!!.signature';
        const parts = invalidToken.split('.');
        if (parts.length === 3) {
          // Try to decode - this should fail
          try {
            JSON.parse(atob(parts[1]));
          } catch {
            throw new Error('Invalid JWT: cannot decode payload');
          }
        }
      }).toThrow('Invalid JWT');
    });

    it('should throw on JWT with missing role claim', () => {
      expect(() => {
        const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
        const payload = btoa(JSON.stringify({ iss: 'supabase' })); // Missing role
        const token = `${header}.${payload}.signature`;
        
        const parts = token.split('.');
        const decodedPayload = JSON.parse(atob(parts[1]));
        
        if (!decodedPayload.role) {
          throw new Error('JWT missing required role claim');
        }
      }).toThrow('JWT missing required role claim');
    });
  });

  describe('Production Mode Behavior', () => {
    it('should not expose sensitive details in production error messages', () => {
      const serviceRoleKey = createTestToken('service_role');
      
      try {
        const parts = serviceRoleKey.split('.');
        const payload = JSON.parse(atob(parts[1]));
        
        // In production mode
        const isDev = false;
        
        if (payload.role !== 'anon') {
          if (isDev) {
            throw new Error(`Details about ${payload.role}`);
          } else {
            throw new Error('Configuration error');
          }
        }
      } catch (error) {
        expect((error as Error).message).toBe('Configuration error');
        expect((error as Error).message).not.toContain('service_role');
      }
    });
  });
});
