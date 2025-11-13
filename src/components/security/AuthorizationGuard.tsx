/**
 * SECURITY: Authorization Guard Component
 * 
 * This component enforces role-based access control for protected UI sections.
 * It should be used in conjunction with server-side authorization checks.
 * 
 * Features:
 * - Hides content from unauthorized users
 * - Handles loading states gracefully
 * - Provides optional fallback UI
 * - Prevents UI flicker during auth initialization
 */

import { ReactNode } from 'react';
import { hasRole, AppRole, User } from '@/security/authorization';

interface AuthorizationGuardProps {
  user: User | null;
  roles: AppRole[];
  isLoading?: boolean;
  fallback?: ReactNode;
  children: ReactNode;
}

/**
 * Guard that only renders children if user has required role(s)
 * 
 * @param user - Current authenticated user
 * @param roles - Array of acceptable roles
 * @param isLoading - Whether auth state is still loading
 * @param fallback - Optional UI to show when unauthorized (defaults to null)
 * @param children - Protected content to render for authorized users
 */
export function AuthorizationGuard({ 
  user, 
  roles, 
  isLoading = false,
  fallback = null,
  children 
}: AuthorizationGuardProps) {
  // During loading, don't expose protected UI
  if (isLoading) {
    return null;
  }

  // Check if user has required role
  const isAuthorized = hasRole(user, roles);

  if (!isAuthorized) {
    return <>{fallback}</>;
  }

  return <>{children}</>;
}
