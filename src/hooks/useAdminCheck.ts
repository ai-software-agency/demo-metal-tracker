import { useState, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';

export const useAdminCheck = () => {
  const [isAdmin, setIsAdmin] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    checkAdminStatus();

    // Listen for auth state changes
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      if (session?.user) {
        setUser(session.user);
        checkAdminStatus();
      } else {
        setUser(null);
        setIsAdmin(false);
        setIsLoading(false);
      }
    });

    return () => subscription.unsubscribe();
  }, []);

  const checkAdminStatus = async () => {
    try {
      setIsLoading(true);
      const {
        data: { session },
      } = await supabase.auth.getSession();

      if (!session) {
        setIsAdmin(false);
        setUser(null);
        setIsLoading(false);
        return;
      }

      setUser(session.user);

      // Call the edge function to check admin status
      const { data, error } = await supabase.functions.invoke('check-admin', {
        headers: {
          Authorization: `Bearer ${session.access_token}`,
        },
      });

      if (error) {
        console.error('Error checking admin status:', error);
        setIsAdmin(false);
      } else if (data?.mfa_required) {
        // Step-up authentication required (MFA or recent auth)
        console.warn('Admin access requires step-up authentication:', data.reason);
        setIsAdmin(false);
        // TODO: Implement MFA challenge flow in the application
        // For now, we just deny admin access
      } else {
        setIsAdmin(data?.isAdmin || false);
      }
    } catch (error) {
      console.error('Error in checkAdminStatus:', error);
      setIsAdmin(false);
    } finally {
      setIsLoading(false);
    }
  };

  return { isAdmin, isLoading, user, refreshAdminStatus: checkAdminStatus };
};
