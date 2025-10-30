import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { RefreshCw, TrendingUp, TrendingDown } from "lucide-react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { fetchSpotPrices, generateHistoricalData } from "@/utils/metalPrices";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

type Timeframe = '7d' | '30d' | '3m' | '6m' | '1y';

const timeframeLabels: Record<Timeframe, string> = {
  '7d': '7 Days',
  '30d': '30 Days',
  '3m': '3 Months',
  '6m': '6 Months',
  '1y': '1 Year'
};

function PriceChartInline({
  data,
  title,
  timeframe,
  onTimeframeChange,
}: {
  data: Array<{ date: string; price: number }>;
  title: string;
  timeframe: Timeframe;
  onTimeframeChange: (tf: Timeframe) => void;
}) {
  return (
    <Card className="p-6 bg-card shadow-card border-border/50">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-4 gap-4">
        <h3 className="text-xl font-bold text-foreground">{title}</h3>
        <div className="flex flex-wrap gap-2">
          {(Object.keys(timeframeLabels) as Timeframe[]).map((tf) => (
            <Button
              key={tf}
              variant={timeframe === tf ? "default" : "outline"}
              size="sm"
              onClick={() => onTimeframeChange(tf)}
              className="text-xs"
            >
              {timeframeLabels[tf]}
            </Button>
          ))}
        </div>
      </div>
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
          <XAxis 
            dataKey="date" 
            stroke="hsl(var(--muted-foreground))"
            tick={{ fill: 'hsl(var(--muted-foreground))' }}
          />
          <YAxis 
            stroke="hsl(var(--muted-foreground))"
            tick={{ fill: 'hsl(var(--muted-foreground))' }}
          />
          <Tooltip 
            contentStyle={{ 
              backgroundColor: 'hsl(var(--card))',
              border: '1px solid hsl(var(--border))',
              borderRadius: '0.5rem'
            }}
            labelStyle={{ color: 'hsl(var(--foreground))' }}
          />
          <Line 
            type="monotone" 
            dataKey="price" 
            stroke="hsl(var(--primary))" 
            strokeWidth={2}
            dot={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </Card>
  );
}

function MetalCardInline({
  name,
  symbol,
  price,
  change,
  changePercent,
  unit = "oz",
}: {
  name: string;
  symbol: string;
  price: number;
  change: number;
  changePercent: number;
  unit?: string;
}) {
  const isPositive = change >= 0;
  return (
    <Card className="p-6 bg-card shadow-card hover:shadow-gold transition-all duration-300 border-border/50 hover:border-primary/30">
      <div className="flex items-start justify-between mb-4">
        <div>
          <h3 className="text-2xl font-bold text-foreground">{name}</h3>
          <p className="text-sm text-muted-foreground">{symbol}</p>
        </div>
        <div className={cn(
          "flex items-center gap-1 px-2 py-1 rounded-md text-sm font-medium",
          isPositive ? "bg-success/10 text-success" : "bg-destructive/10 text-destructive"
        )}>
          {isPositive ? <TrendingUp className="h-4 w-4" /> : <TrendingDown className="h-4 w-4" />}
          {changePercent.toFixed(2)}%
        </div>
      </div>
      <div className="space-y-2">
        <div className="flex items-baseline gap-2">
          <span className="text-3xl font-bold bg-gradient-gold bg-clip-text text-transparent">
            ${price.toFixed(2)}
          </span>
          <span className="text-sm text-muted-foreground">/{unit}</span>
        </div>
        <div className={cn(
          "text-sm font-medium",
          isPositive ? "text-success" : "text-destructive"
        )}>
          {isPositive ? "+" : ""}{change.toFixed(2)} ({isPositive ? "+" : ""}{changePercent.toFixed(2)}%)
        </div>
      </div>
    </Card>
  );
}

const SpotPrices = () => {
  const { toast } = useToast();
  const [lastUpdate, setLastUpdate] = useState(new Date());
  const [goldTimeframe, setGoldTimeframe] = useState<Timeframe>('30d');
  const [silverTimeframe, setSilverTimeframe] = useState<Timeframe>('30d');

  const { data: prices, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['spotPrices'],
    queryFn: fetchSpotPrices,
  });

  const goldData = useMemo(() => 
    generateHistoricalData(prices?.[0]?.price || 4019, goldTimeframe),
    [prices, goldTimeframe]
  );

  const silverData = useMemo(() => 
    generateHistoricalData(prices?.[1]?.price || 48, silverTimeframe),
    [prices, silverTimeframe]
  );

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
                <MetalCardInline key={metal.symbol} {...metal} />
              ))}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <PriceChartInline 
                data={goldData}
                title="Gold - Price Trend"
                timeframe={goldTimeframe}
                onTimeframeChange={setGoldTimeframe}
              />
              <PriceChartInline 
                data={silverData}
                title="Silver - Price Trend"
                timeframe={silverTimeframe}
                onTimeframeChange={setSilverTimeframe}
              />
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default SpotPrices;
