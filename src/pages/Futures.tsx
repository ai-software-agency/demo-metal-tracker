import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { RefreshCw, TrendingUp, TrendingDown } from "lucide-react";
import { fetchFuturesPrices } from "@/utils/metalPrices";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

const Futures = () => {
  const { toast } = useToast();
  const [lastUpdate, setLastUpdate] = useState(new Date());

  const { data: futures, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['futuresPrices'],
    queryFn: fetchFuturesPrices,
  });

  const handleRefresh = async () => {
    setLastUpdate(new Date());
    await refetch();
    toast({
      title: "Futures Updated",
      description: "Latest futures prices have been fetched",
    });
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto px-4 py-8">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h2 className="text-3xl font-bold text-foreground mb-2">Metal Futures</h2>
            <p className="text-muted-foreground">
              Last updated: {lastUpdate.toLocaleTimeString()}
            </p>
          </div>
          <Button 
            onClick={handleRefresh} 
            disabled={isFetching}
            className="gap-2"
          >
            <RefreshCw className={`h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>

        {isLoading ? (
          <div className="space-y-4">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-32 bg-card animate-pulse rounded-lg" />
            ))}
          </div>
        ) : (
          <div className="space-y-4">
            {futures?.map((future) => {
              const isPositive = future.change >= 0;
              
              return (
                <Card 
                  key={future.contract} 
                  className="p-6 bg-card shadow-card hover:shadow-gold transition-all duration-300 border-border/50 hover:border-primary/30"
                >
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <h3 className="text-xl font-bold text-foreground">{future.name} Futures</h3>
                          <p className="text-sm text-muted-foreground">{future.contract}</p>
                        </div>
                        <div className={cn(
                          "flex items-center gap-1 px-2 py-1 rounded-md text-sm font-medium",
                          isPositive ? "bg-success/10 text-success" : "bg-destructive/10 text-destructive"
                        )}>
                          {isPositive ? <TrendingUp className="h-4 w-4" /> : <TrendingDown className="h-4 w-4" />}
                          {future.changePercent.toFixed(2)}%
                        </div>
                      </div>
                      <div className="flex items-baseline gap-2 mb-2">
                        <span className="text-2xl font-bold bg-gradient-gold bg-clip-text text-transparent">
                          ${future.price.toFixed(2)}
                        </span>
                        <span className="text-sm text-muted-foreground">/{future.unit}</span>
                      </div>
                      <div className={cn(
                        "text-sm font-medium",
                        isPositive ? "text-success" : "text-destructive"
                      )}>
                        {isPositive ? "+" : ""}{future.change.toFixed(2)} ({isPositive ? "+" : ""}{future.changePercent.toFixed(2)}%)
                      </div>
                    </div>
                    <div className="flex flex-col items-start md:items-end gap-1">
                      <span className="text-xs text-muted-foreground">Expiry</span>
                      <span className="text-sm font-medium text-foreground">{future.expiryDate}</span>
                    </div>
                  </div>
                </Card>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

export default Futures;
