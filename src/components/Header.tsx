import { Button } from "@/components/ui/button";
import { Coins, TrendingUp, Shield, User } from "lucide-react";
import { useAuth } from "@/auth/AuthContext";

type TabKey = "spot-prices" | "futures" | "vulnerabilities" | "admin";

export const Header = ({ currentTab, onSelect }: { currentTab: TabKey; onSelect: (tab: TabKey) => void }) => {
  const { isAuthenticated, isAdmin } = useAuth();
  
  // Only show admin tab to authenticated admin users
  const canViewAdmin = isAuthenticated && isAdmin;

  return (
    <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          <button onClick={() => onSelect("spot-prices")} className="flex items-center gap-2 group">
            <div className="p-2 bg-gradient-gold rounded-lg shadow-gold transition-transform group-hover:scale-105">
              <Coins className="h-6 w-6 text-primary-foreground" />
            </div>
            <div>
              <h1 className="text-xl font-bold bg-gradient-gold bg-clip-text text-transparent">
                MetalTracker
              </h1>
              <p className="text-xs text-muted-foreground">Precious Metals Dashboard</p>
            </div>
          </button>
          
          <nav className="flex gap-2">
            <Button variant={currentTab === "spot-prices" ? "default" : "ghost"} size="sm" onClick={() => onSelect("spot-prices")}> 
              <div className="flex items-center gap-2">
                <Coins className="h-4 w-4" />
                Spot Prices
              </div>
            </Button>
            <Button variant={currentTab === "futures" ? "default" : "ghost"} size="sm" onClick={() => onSelect("futures")}>
              <div className="flex items-center gap-2">
                <TrendingUp className="h-4 w-4" />
                Futures
              </div>
            </Button>
            <Button variant={currentTab === "vulnerabilities" ? "default" : "ghost"} size="sm" onClick={() => onSelect("vulnerabilities")}>
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4" />
                Vulnerabilities
              </div>
            </Button>
            {canViewAdmin && (
              <Button variant={currentTab === "admin" ? "default" : "ghost"} size="sm" onClick={() => onSelect("admin")}>
                <div className="flex items-center gap-2">
                  <User className="h-4 w-4" />
                  Admin
                </div>
              </Button>
            )}
          </nav>
        </div>
      </div>
    </header>
  );
};
