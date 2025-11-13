/**
 * SECURITY FIX: Broken Access Control Prevention
 * 
 * AdminPanel now requires:
 * 1. Authentication (user must be logged in)
 * 2. Authorization (user must have admin role)
 * 
 * Guards prevent unauthorized mounting via:
 * - Direct tab selection through Header
 * - Programmatic navigation via onNavigate
 * 
 * Admin tab is hidden in Header for non-admin users to reduce discoverability.
 */
import { Toaster } from "@/components/ui/toaster";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Header } from "@/components/Header";
import SpotPrices from "./pages/SpotPrices";
import Futures from "./pages/Futures";
import VulnerabilityTest from "./pages/VulnerabilityTest";
import AdminPanel from "./pages/AdminPanel";
import { useState } from "react";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import { RequireAuth } from "./auth/RequireAuth";
import { RequireRole } from "./auth/RequireRole";
import { AccessDenied } from "./components/AccessDenied";

const queryClient = new QueryClient();

type TabKey = "spot-prices" | "futures" | "vulnerabilities" | "admin";

const AppContent = () => {
  const [tab, setTab] = useState<TabKey>("spot-prices");
  const { isAuthenticated, isAdmin } = useAuth();

  // Guarded tab setter: prevents unauthorized access to admin tab
  const setTabGuarded = (next: TabKey) => {
    if (next === "admin") {
      // Prevent non-authenticated or non-admin users from accessing admin tab
      if (!isAuthenticated || !isAdmin) {
        return; // Silently ignore unauthorized navigation attempts
      }
    }
    setTab(next);
  };

  return (
    <>
      <Toaster />
      <Header currentTab={tab} onSelect={setTabGuarded} />
      {tab === "spot-prices" && <SpotPrices />}
      {tab === "futures" && <Futures />}
      {tab === "vulnerabilities" && <VulnerabilityTest onNavigate={setTabGuarded} />}
      {tab === "admin" && (
        <RequireAuth>
          <RequireRole roles={["admin"]}>
            <AdminPanel />
          </RequireRole>
        </RequireAuth>
      )}
    </>
  );
};

const App = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </QueryClientProvider>
  );
};

export default App;
