import { ReactNode } from 'react';
import { useAuth } from './AuthContext';
import { AccessDenied } from '@/components/AccessDenied';

interface RequireRoleProps {
  children: ReactNode;
  roles: string[];
}

export const RequireRole = ({ children, roles }: RequireRoleProps) => {
  const { isAdmin, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <p className="text-muted-foreground">Loading...</p>
      </div>
    );
  }

  // Check if user has required role (currently only 'admin' is supported)
  const hasRequiredRole = roles.includes('admin') ? isAdmin : false;

  if (!hasRequiredRole) {
    return <AccessDenied message="You do not have permission to access this page." statusCode={403} />;
  }

  return <>{children}</>;
};
