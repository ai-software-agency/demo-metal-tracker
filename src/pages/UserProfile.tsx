import { useState, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";

const UserProfile = () => {
  const { toast } = useToast();
  const [userId, setUserId] = useState("");
  const [userData, setUserData] = useState<any>(null);
  const [comment, setComment] = useState("");
  const [comments, setComments] = useState<string[]>([]);

  // Mock database
  const mockDatabase: Record<string, any> = {
    "1": { name: "John Doe", email: "john@example.com", balance: "$50,000", ssn: "123-45-6789" },
    "2": { name: "Jane Smith", email: "jane@example.com", balance: "$75,000", ssn: "987-65-4321" },
    "3": { name: "Bob Johnson", email: "bob@example.com", balance: "$100,000", ssn: "456-78-9012" }
  };

  const loadUserData = () => {
    // VULNERABILITY 9: Insecure Direct Object Reference (IDOR)
    // Any user can access any other user's data by changing the ID
    const user = mockDatabase[userId];
    if (user) {
      setUserData(user);
      toast({
        title: "Profile Loaded",
        description: `Viewing profile for user ${userId}`,
      });
    } else {
      toast({
        title: "User Not Found",
        variant: "destructive",
      });
    }
  };

  const addComment = () => {
    // VULNERABILITY 10: XSS - No sanitization of user input
    // Users can inject scripts via comments
    setComments([...comments, comment]);
    setComment("");
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto px-4 py-8">
        <h2 className="text-3xl font-bold mb-8 text-foreground">User Profile Viewer</h2>
        
        <Card className="p-6 mb-6">
          <h3 className="text-xl font-bold mb-4">⚠️ IDOR Vulnerability Demo</h3>
          <p className="text-muted-foreground mb-4">
            Try different user IDs (1, 2, 3) to access ANY user's sensitive data!
          </p>
          <div className="flex gap-4">
            <Input
              placeholder="Enter User ID (1, 2, or 3)"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
            />
            <Button onClick={loadUserData}>Load Profile</Button>
          </div>
        </Card>

        {userData && (
          <Card className="p-6 mb-6">
            <h3 className="text-xl font-bold mb-4">User Information</h3>
            <div className="space-y-2">
              <p><strong>Name:</strong> {userData.name}</p>
              <p><strong>Email:</strong> {userData.email}</p>
              <p className="text-destructive"><strong>Balance:</strong> {userData.balance}</p>
              <p className="text-destructive"><strong>SSN:</strong> {userData.ssn}</p>
            </div>
          </Card>
        )}

        <Card className="p-6">
          <h3 className="text-xl font-bold mb-4">⚠️ XSS Vulnerability Demo</h3>
          <p className="text-muted-foreground mb-4">
            Try entering: &lt;img src=x onerror=alert('XSS')&gt;
          </p>
          <div className="flex gap-4 mb-4">
            <Input
              placeholder="Enter comment (no sanitization!)"
              value={comment}
              onChange={(e) => setComment(e.target.value)}
            />
            <Button onClick={addComment}>Add Comment</Button>
          </div>
          <div className="space-y-2">
            {comments.map((c, i) => (
              <div 
                key={i} 
                className="p-3 bg-secondary rounded"
                // VULNERABILITY: dangerouslySetInnerHTML without sanitization
                dangerouslySetInnerHTML={{ __html: c }}
              />
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
};

export default UserProfile;
