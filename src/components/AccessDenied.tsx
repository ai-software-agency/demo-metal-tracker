import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ShieldAlert } from "lucide-react";

interface AccessDeniedProps {
  message?: string;
  statusCode?: 401 | 403;
}

export const AccessDenied = ({ 
  message = "Access denied",
  statusCode = 403 
}: AccessDeniedProps) => {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <Card className="p-8 max-w-md w-full text-center">
        <div className="flex justify-center mb-4">
          <div className="p-3 bg-destructive/10 rounded-full">
            <ShieldAlert className="h-12 w-12 text-destructive" />
          </div>
        </div>
        <h2 className="text-2xl font-bold mb-2 text-foreground">
          {statusCode === 401 ? "Authentication Required" : "Access Denied"}
        </h2>
        <p className="text-muted-foreground mb-6">{message}</p>
        <div className="flex gap-2 justify-center">
          <Button 
            variant="outline" 
            onClick={() => window.location.href = '/'}
          >
            Go Home
          </Button>
        </div>
      </Card>
    </div>
  );
};
