// Mock data for demonstration - In production, this would fetch from an API
export interface MetalPrice {
  name: string;
  symbol: string;
  price: number;
  change: number;
  changePercent: number;
  unit: string;
}

export interface FuturePrice extends MetalPrice {
  expiryDate: string;
  contract: string;
}

// Generate realistic price variations
const getRandomVariation = (base: number, variance: number) => {
  return base + (Math.random() - 0.5) * variance;
};

export const fetchSpotPrices = async (): Promise<MetalPrice[]> => {
  // Simulate API delay
  await new Promise(resolve => setTimeout(resolve, 500));
  
  const baseGold = 4019;
  const baseSilver = 48.0;
  const basePlatinum = 960;
  const basePalladium = 920;
  
  return [
    {
      name: "Gold",
      symbol: "XAU",
      price: getRandomVariation(baseGold, 15),
      change: getRandomVariation(25, 15),
      changePercent: getRandomVariation(0.6, 0.4),
      unit: "oz"
    },
    {
      name: "Silver",
      symbol: "XAG",
      price: getRandomVariation(baseSilver, 0.8),
      change: getRandomVariation(0.6, 0.4),
      changePercent: getRandomVariation(1.3, 0.7),
      unit: "oz"
    },
    {
      name: "Platinum",
      symbol: "XPT",
      price: getRandomVariation(basePlatinum, 15),
      change: getRandomVariation(-5, 8),
      changePercent: getRandomVariation(-0.5, 0.8),
      unit: "oz"
    },
    {
      name: "Palladium",
      symbol: "XPD",
      price: getRandomVariation(basePalladium, 15),
      change: getRandomVariation(-8, 12),
      changePercent: getRandomVariation(-0.9, 1.3),
      unit: "oz"
    }
  ];
};

export const fetchFuturesPrices = async (): Promise<FuturePrice[]> => {
  await new Promise(resolve => setTimeout(resolve, 500));
  
  return [
    {
      name: "Gold",
      symbol: "GC",
      contract: "GC=F",
      price: getRandomVariation(4025, 20),
      change: getRandomVariation(28, 15),
      changePercent: getRandomVariation(0.7, 0.5),
      unit: "oz",
      expiryDate: "Dec 2025"
    },
    {
      name: "Silver",
      symbol: "SI",
      contract: "SI=F",
      price: getRandomVariation(48.5, 0.8),
      change: getRandomVariation(0.7, 0.4),
      changePercent: getRandomVariation(1.5, 0.8),
      unit: "oz",
      expiryDate: "Dec 2025"
    },
    {
      name: "Platinum",
      symbol: "PL",
      contract: "PL=F",
      price: getRandomVariation(955, 15),
      change: getRandomVariation(-3, 8),
      changePercent: getRandomVariation(-0.3, 0.8),
      unit: "oz",
      expiryDate: "Jan 2026"
    },
    {
      name: "Copper",
      symbol: "HG",
      contract: "HG=F",
      price: getRandomVariation(3.85, 0.1),
      change: getRandomVariation(0.05, 0.05),
      changePercent: getRandomVariation(1.3, 0.7),
      unit: "lb",
      expiryDate: "Dec 2025"
    }
  ];
};

export const generateHistoricalData = (basePrice: number, timeframe: '7d' | '30d' | '3m' | '6m' | '1y') => {
  const daysMap = {
    '7d': 7,
    '30d': 30,
    '3m': 90,
    '6m': 180,
    '1y': 365
  };
  
  const days = daysMap[timeframe];
  const data = [];
  
  // Calculate realistic starting price based on current price and timeframe
  // Gold went from ~$2000 to ~$4019 over a year (roughly doubled)
  // Silver went from ~$24 to ~$48 over a year (also roughly doubled)
  const isGold = basePrice > 1000;
  const isSilver = basePrice > 20 && basePrice < 100;
  
  let growthFactor;
  if (isGold) {
    // Gold growth patterns
    growthFactor = days === 7 ? 0.98 : days === 30 ? 0.95 : days === 90 ? 0.85 : days === 180 ? 0.70 : 0.50;
  } else if (isSilver) {
    // Silver growth patterns
    growthFactor = days === 7 ? 0.98 : days === 30 ? 0.94 : days === 90 ? 0.82 : days === 180 ? 0.68 : 0.48;
  } else {
    // Other metals - more moderate growth
    growthFactor = days === 7 ? 0.99 : days === 30 ? 0.97 : days === 90 ? 0.92 : days === 180 ? 0.85 : 0.75;
  }
  
  let startPrice = basePrice * growthFactor;
  const totalGrowth = basePrice - startPrice;
  
  for (let i = days; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    
    // Calculate progressive growth with realistic volatility
    const progress = 1 - (i / days);
    const trendPrice = startPrice + (totalGrowth * progress);
    
    // Add realistic daily volatility (1-3% swings)
    const volatility = basePrice * 0.015;
    const dailyVariation = (Math.random() - 0.5) * volatility;
    
    // Add some wave patterns for realism
    const wavePattern = Math.sin(progress * Math.PI * 4) * (basePrice * 0.01);
    
    const price = trendPrice + dailyVariation + wavePattern;
    
    data.push({
      date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      price: parseFloat(price.toFixed(2))
    });
  }
  
  return data;
};
