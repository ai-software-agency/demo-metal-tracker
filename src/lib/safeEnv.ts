/**
 * SECURITY: Safe Environment Variable Validation
 * 
 * This module validates Supabase credentials at runtime to ensure:
 * 1. Required environment variables are present
 * 2. Only anon (public) keys are used in client code, never service_role keys
 * 3. Clear error messages in development, safe failures in production
 * 
 * This prevents accidental exposure of admin credentials in client bundles.
 */

interface SupabaseClientEnv {
  url: string;
  anonKey: string;
  projectId: string;
}

/**
 * Decode JWT payload without verification (client-side only, for role checking)
 * Returns null if decoding fails
 */
function decodeJWTPayload(token: string): { role?: string } | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }
    
    // Base64url decode the payload (middle part)
    const payload = parts[1];
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = atob(base64);
    return JSON.parse(jsonPayload);
  } catch {
    return null;
  }
}

/**
 * Validate that the provided key is an anon key, not a service_role or other privileged key
 * Throws clear errors in development, generic errors in production
 */
function validateAnonKey(key: string | undefined, isDev: boolean): void {
  if (!key || key.includes('<your-anon-key>') || key === '') {
    const message = 'VITE_SUPABASE_PUBLISHABLE_KEY is not configured';
    if (isDev) {
      throw new Error(`${message}. Copy .env.example to .env and configure your Supabase credentials.`);
    }
    throw new Error('Application configuration error');
  }

  const payload = decodeJWTPayload(key);
  
  if (!payload) {
    const message = 'Invalid Supabase key format';
    if (isDev) {
      throw new Error(`${message}. Expected a valid JWT token.`);
    }
    throw new Error('Application configuration error');
  }

  // SECURITY: Reject service_role or any non-anon keys in client code
  if (payload.role !== 'anon') {
    const message = `Dangerous key detected: role="${payload.role}"`;
    if (isDev) {
      throw new Error(
        `${message}. NEVER use service_role or admin keys in client code! ` +
        `These keys grant full database access and must only be used server-side. ` +
        `Use the anon key (VITE_SUPABASE_PUBLISHABLE_KEY) instead.`
      );
    }
    // In production, fail safely without exposing details
    throw new Error('Application configuration error');
  }
}

/**
 * Get and validate Supabase client environment variables
 * Called once at application startup to fail fast on misconfiguration
 */
export function getClientEnv(): SupabaseClientEnv {
  const isDev = import.meta.env.DEV;
  
  const url = import.meta.env.VITE_SUPABASE_URL;
  const anonKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;
  const projectId = import.meta.env.VITE_SUPABASE_PROJECT_ID;

  // Validate URL
  if (!url || url.includes('<your-project-ref>') || url === '') {
    const message = 'VITE_SUPABASE_URL is not configured';
    if (isDev) {
      console.warn(`${message}. The environment variables should be auto-managed by Lovable Cloud.`);
      // In Lovable Cloud, allow the app to continue even if env vars aren't loaded yet
      return {
        url: '',
        anonKey: '',
        projectId: '',
      };
    }
    throw new Error('Application configuration error');
  }

  // Validate project ID
  if (!projectId || projectId.includes('<your-project-ref>') || projectId === '') {
    const message = 'VITE_SUPABASE_PROJECT_ID is not configured';
    if (isDev) {
      console.warn(`${message}. The environment variables should be auto-managed by Lovable Cloud.`);
      // In Lovable Cloud, allow the app to continue even if env vars aren't loaded yet
      return {
        url: '',
        anonKey: '',
        projectId: '',
      };
    }
    throw new Error('Application configuration error');
  }

  // SECURITY: Validate that only anon keys are used
  validateAnonKey(anonKey, isDev);

  return {
    url,
    anonKey: anonKey!,
    projectId,
  };
}

/**
 * Initialize and validate environment at app startup
 * This runs synchronously before React renders to catch misconfigurations early
 */
export function initializeEnv(): void {
  try {
    getClientEnv();
    console.log('[Security] Environment validation passed');
  } catch (error) {
    console.error('[Security] Environment validation failed:', error);
    throw error;
  }
}
