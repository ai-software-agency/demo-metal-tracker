import { ReactNode } from 'react';
import { useAuth } from './AuthContext';
import { AccessDenied } from '@/components/AccessDenied';

interface RequireAuthProps {
  children: ReactNode;
}

export const RequireAuth = ({ children }: RequireAuthProps) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <p className="text-muted-foreground">Loading...</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <AccessDenied message="You must be logged in to access this page." statusCode={401} />;
  }

  return <>{children}</>;
};
