import { Toaster } from "@/components/ui/toaster";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Header } from "@/components/Header";
import SpotPrices from "./pages/SpotPrices";
import Futures from "./pages/Futures";
import VulnerabilityTest from "./pages/VulnerabilityTest";
import AdminPanel from "./pages/AdminPanel";
import { useState } from "react";

const queryClient = new QueryClient();

type TabKey = "spot-prices" | "futures" | "vulnerabilities" | "admin";

const App = () => {
  const [tab, setTab] = useState<TabKey>("spot-prices");

  return (
    <QueryClientProvider client={queryClient}>
      <Toaster />
      <Header currentTab={tab} onSelect={setTab} />
      {tab === "spot-prices" && <SpotPrices />}
      {tab === "futures" && <Futures />}
      {tab === "vulnerabilities" && <VulnerabilityTest onNavigate={setTab} />}
      {tab === "admin" && <AdminPanel />}
    </QueryClientProvider>
  );
};

export default App;
