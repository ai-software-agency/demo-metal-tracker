import { Button } from "@/components/ui/button";
import { Coins, TrendingUp, Shield, User } from "lucide-react";
import { Link, useLocation } from "react-router-dom";

export const Header = () => {
  const location = useLocation();
  
  return (
    <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2 group">
            <div className="p-2 bg-gradient-gold rounded-lg shadow-gold transition-transform group-hover:scale-105">
              <Coins className="h-6 w-6 text-primary-foreground" />
            </div>
            <div>
              <h1 className="text-xl font-bold bg-gradient-gold bg-clip-text text-transparent">
                MetalTracker
              </h1>
              <p className="text-xs text-muted-foreground">Precious Metals Dashboard</p>
            </div>
          </Link>
          
          <nav className="flex gap-2">
            <Button
              variant={location.pathname === "/spot-prices" ? "default" : "ghost"}
              asChild
              size="sm"
            >
              <Link to="/spot-prices" className="flex items-center gap-2">
                <Coins className="h-4 w-4" />
                Spot Prices
              </Link>
            </Button>
            <Button
              variant={location.pathname === "/futures" ? "default" : "ghost"}
              asChild
              size="sm"
            >
              <Link to="/futures" className="flex items-center gap-2">
                <TrendingUp className="h-4 w-4" />
                Futures
              </Link>
            </Button>
            <Button
              variant={location.pathname === "/vulnerabilities" ? "default" : "ghost"}
              asChild
              size="sm"
            >
              <Link to="/vulnerabilities" className="flex items-center gap-2">
                <Shield className="h-4 w-4" />
                Vulnerabilities
              </Link>
            </Button>
            <Button
              variant={location.pathname === "/admin" ? "default" : "ghost"}
              asChild
              size="sm"
            >
              <Link to="/admin" className="flex items-center gap-2">
                <User className="h-4 w-4" />
                Admin
              </Link>
            </Button>
          </nav>
        </div>
      </div>
    </header>
  );
};
