import { Card } from "@/components/ui/card";
import { TrendingUp, TrendingDown } from "lucide-react";
import { cn } from "@/lib/utils";

interface MetalCardProps {
  name: string;
  symbol: string;
  price: number;
  change: number;
  changePercent: number;
  unit?: string;
}

export const MetalCard = ({ 
  name, 
  symbol, 
  price, 
  change, 
  changePercent,
  unit = "oz"
}: MetalCardProps) => {
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
};
