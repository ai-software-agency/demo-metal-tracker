import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { MetalCard } from "@/components/MetalCard";
import { PriceChart } from "@/components/PriceChart";
import { RefreshCw } from "lucide-react";
import { fetchSpotPrices, generateHistoricalData } from "@/utils/metalPrices";
import { useToast } from "@/hooks/use-toast";

const SpotPrices = () => {
  const { toast } = useToast();
  const [lastUpdate, setLastUpdate] = useState(new Date());

  const { data: prices, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['spotPrices'],
    queryFn: fetchSpotPrices,
  });

  const handleRefresh = async () => {
    setLastUpdate(new Date());
    await refetch();
    toast({
      title: "Prices Updated",
      description: "Latest spot prices have been fetched",
    });
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto px-4 py-8">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h2 className="text-3xl font-bold text-foreground mb-2">Spot Prices</h2>
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
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-40 bg-card animate-pulse rounded-lg" />
            ))}
          </div>
        ) : (
          <>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
              {prices?.map((metal) => (
                <MetalCard key={metal.symbol} {...metal} />
              ))}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <PriceChart 
                data={generateHistoricalData(prices?.[0]?.price || 2050, 30)}
                title="Gold - 30 Day Trend"
              />
              <PriceChart 
                data={generateHistoricalData(prices?.[1]?.price || 24.5, 30)}
                title="Silver - 30 Day Trend"
              />
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default SpotPrices;
