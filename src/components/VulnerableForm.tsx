import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";

export const VulnerableForm = () => {
  const { toast } = useToast();
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
    creditCard: "",
    message: ""
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
      <p className="text-muted-foreground mb-4">
        This form has multiple vulnerabilities: no validation, plaintext logging, no CSRF protection
      </p>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="text-sm font-medium mb-2 block">Username (no validation)</label>
          <Input
            value={formData.username}
            onChange={(e) => setFormData({...formData, username: e.target.value})}
            placeholder="Enter any text, including scripts"
          />
        </div>
        
        <div>
          <label className="text-sm font-medium mb-2 block">Email (no validation)</label>
          <Input
            value={formData.email}
            onChange={(e) => setFormData({...formData, email: e.target.value})}
            placeholder="not-an-email is accepted"
          />
        </div>
        
        <div>
          <label className="text-sm font-medium mb-2 block">Password (logged in plaintext)</label>
          <Input
            type="password"
            value={formData.password}
            onChange={(e) => setFormData({...formData, password: e.target.value})}
            placeholder="Will be logged to console"
          />
        </div>
        
        <div>
          <label className="text-sm font-medium mb-2 block">Credit Card (no masking)</label>
          <Input
            value={formData.creditCard}
            onChange={(e) => setFormData({...formData, creditCard: e.target.value})}
            placeholder="1234-5678-9012-3456"
          />
        </div>
        
        <div>
          <label className="text-sm font-medium mb-2 block">Message (XSS vulnerable)</label>
          <Textarea
            value={formData.message}
            onChange={(e) => setFormData({...formData, message: e.target.value})}
            placeholder="Try: <script>alert('XSS')</script>"
          />
        </div>
        
        <Button type="submit" className="w-full">
          Submit (Insecurely)
        </Button>
      </form>
      
      <div className="mt-6 p-4 bg-destructive/10 border border-destructive rounded">
        <h4 className="font-bold text-destructive mb-2">Vulnerabilities in this form:</h4>
        <ul className="text-sm space-y-1 text-destructive">
          <li>✗ No input validation</li>
          <li>✗ No email format checking</li>
          <li>✗ Credit card data not validated/masked</li>
          <li>✗ XSS vulnerable text areas</li>
          <li>✗ No CSRF protection</li>
          <li>✗ No rate limiting</li>
        </ul>
      </div>
    </Card>
  );
};
