/**
 * SECURITY: Authorization Utilities
 * 
 * Centralized role-based access control (RBAC) helpers.
 * Always use these functions for client-side authorization checks.
 * 
 * IMPORTANT: These are client-side guards only. All sensitive operations
 * MUST be protected server-side with proper authorization middleware.
 */

export type AppRole = 'admin' | 'moderator' | 'user';

export interface User {
  id: string;
  email: string;
  role?: AppRole;
}

/**
 * Check if a user has any of the specified roles
 * Fails closed: returns false if user is null/undefined or has no role
 * 
 * @param user - The authenticated user object (or null)
 * @param roles - Array of acceptable roles
 * @returns true if user has at least one of the specified roles
 */
export function hasRole(user: User | null | undefined, roles: AppRole[]): boolean {
  if (!user || !user.role) {
    return false;
  }
  return roles.includes(user.role);
}

/**
 * Check if a user is an admin
 * Convenience wrapper around hasRole(['admin'])
 * 
 * @param user - The authenticated user object (or null)
 * @returns true if user has admin role
 */
export function isAdmin(user: User | null | undefined): boolean {
  return hasRole(user, ['admin']);
}

/**
 * Check if a user is a moderator or admin
 * 
 * @param user - The authenticated user object (or null)
 * @returns true if user has moderator or admin role
 */
export function isModerator(user: User | null | undefined): boolean {
  return hasRole(user, ['admin', 'moderator']);
}
