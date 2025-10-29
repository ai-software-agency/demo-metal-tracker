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
  let price = basePrice;
  
  for (let i = days; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    
    // Add some realistic variation
    price = price + (Math.random() - 0.5) * (basePrice * 0.02);
    
    data.push({
      date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
      price: parseFloat(price.toFixed(2))
    });
  }
  
  return data;
};
