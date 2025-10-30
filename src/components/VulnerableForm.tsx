import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";

export const VulnerableForm = () => {
  const { toast } = useToast();
  const [formData, setFormData] = useState({
    email: "",
    creditCard: "",
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    toast({
      title: "Form Submitted",
      description: "Form submitted successfully",
    });
  };

  return (
    <Card className="p-6 max-w-2xl mx-auto">
      <h3 className="text-xl font-bold mb-4">⚠️ Vulnerable Contact Form</h3>
      <p className="text-muted-foreground mb-4">This form intentionally lacks validation for two fields.</p>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="text-sm font-medium mb-2 block">Email (no validation)</label>
          <Input
            value={formData.email}
            onChange={(e) => setFormData({...formData, email: e.target.value})}
            placeholder="not-an-email is accepted"
          />
        </div>

        <div>
          <label className="text-sm font-medium mb-2 block">Credit Card (no validation/masking)</label>
          <Input
            value={formData.creditCard}
            onChange={(e) => setFormData({...formData, creditCard: e.target.value})}
            placeholder="1234-5678-9012-3456"
          />
        </div>
        
        <Button type="submit" className="w-full">
          Submit (Insecurely)
        </Button>
      </form>
      
      <div className="mt-6 p-4 bg-destructive/10 border border-destructive rounded">
        <h4 className="font-bold text-destructive mb-2">Input Validation Issues (2)</h4>
        <ul className="text-sm space-y-1 text-destructive">
          <li>✗ Email format not validated</li>
          <li>✗ Credit card not validated/masked</li>
        </ul>
      </div>
    </Card>
  );
};
