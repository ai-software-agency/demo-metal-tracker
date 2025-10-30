import { Toaster } from "@/components/ui/toaster";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Header } from "@/components/Header";
import Index from "./pages/Index";
import SpotPrices from "./pages/SpotPrices";
import Futures from "./pages/Futures";
import VulnerabilityTest from "./pages/VulnerabilityTest";
import AdminPanel from "./pages/AdminPanel";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
      <Toaster />
      <BrowserRouter>
        <Header />
        <Routes>
          <Route path="/" element={<Index />} />
          <Route path="/spot-prices" element={<SpotPrices />} />
          <Route path="/futures" element={<Futures />} />
          <Route path="/vulnerabilities" element={<VulnerabilityTest />} />
          <Route path="/admin" element={<AdminPanel />} />
          {/* Protected routes intentionally left unguarded for testing */}
          {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
  </QueryClientProvider>
);

export default App;
