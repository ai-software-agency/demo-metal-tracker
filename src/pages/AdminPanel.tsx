import { useState, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { Trash2, UserPlus } from "lucide-react";

// VULNERABILITY 1: Exposed API Key in source code
const ADMIN_API_KEY = "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";

// VULNERABILITY 2: Hardcoded admin credentials
const ADMIN_PASSWORD = "admin123";

const AdminPanel = () => {
  const { toast } = useToast();
  const [isAdmin, setIsAdmin] = useState(false);
  const [password, setPassword] = useState("");
  const [userEmail, setUserEmail] = useState("");
  const [userRole, setUserRole] = useState("");
  const [users, setUsers] = useState<any[]>([]);

  useEffect(() => {
    // VULNERABILITY 3: Client-side authentication check using localStorage
    const adminStatus = localStorage.getItem("isAdmin");
    if (adminStatus === "true") {
      setIsAdmin(true);
      loadUsers();
    }
  }, []);

  const handleLogin = () => {
    // VULNERABILITY 4: Weak authentication - hardcoded password
    if (password === ADMIN_PASSWORD) {
      setIsAdmin(true);
      localStorage.setItem("isAdmin", "true");
      toast({
        title: "Admin Access Granted",
        description: "Welcome to the admin panel",
      });
      loadUsers();
    } else {
      toast({
        title: "Access Denied",
        description: "Invalid password",
        variant: "destructive",
      });
    }
  };

  const loadUsers = () => {
    // VULNERABILITY 5: Insecure direct object reference - loading all user data
    const mockUsers = [
      { id: 1, email: "john@example.com", role: "admin", ssn: "123-45-6789", creditCard: "4532-1234-5678-9012" },
      { id: 2, email: "jane@example.com", role: "user", ssn: "987-65-4321", creditCard: "5678-9012-3456-7890" },
      { id: 3, email: "bob@example.com", role: "user", ssn: "456-78-9012", creditCard: "9012-3456-7890-1234" }
    ];
    setUsers(mockUsers);
  };

  const deleteUser = (userId: number) => {
    // VULNERABILITY 6: No confirmation or validation before deletion
    setUsers(users.filter(u => u.id !== userId));
    toast({
      title: "User Deleted",
      description: `User ${userId} has been removed`,
    });
  };

  const addUser = () => {
    // VULNERABILITY 7: No input validation or sanitization
    const newUser = {
      id: users.length + 1,
      email: userEmail, // No email validation
      role: userRole,   // No role validation
      ssn: "000-00-0000",
      creditCard: "0000-0000-0000-0000"
    };
    setUsers([...users, newUser]);
    
    // VULNERABILITY 8: Logging sensitive data
    console.log("Added new user:", newUser);
    console.log("Admin API Key:", ADMIN_API_KEY);
    
    setUserEmail("");
    setUserRole("");
  };

  if (!isAdmin) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Card className="p-8 max-w-md w-full">
          <h2 className="text-2xl font-bold mb-4 text-foreground">Admin Login</h2>
          <p className="text-sm text-muted-foreground mb-4">
            Hint: The password is visible in the source code 😉
          </p>
          <Input
            type="password"
            placeholder="Admin Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mb-4"
          />
          <Button onClick={handleLogin} className="w-full">
            Login
          </Button>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto px-4 py-8">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h2 className="text-3xl font-bold text-foreground">Admin Panel</h2>
            <p className="text-muted-foreground">⚠️ Warning: This page has security vulnerabilities!</p>
          </div>
          <Button 
            variant="destructive"
            onClick={() => {
              setIsAdmin(false);
              localStorage.removeItem("isAdmin");
            }}
          >
            Logout
          </Button>
        </div>

        <div className="grid gap-6 mb-8">
          <Card className="p-6">
            <h3 className="text-xl font-bold mb-4">Add New User</h3>
            <div className="flex gap-4">
              <Input
                placeholder="Email (no validation)"
                value={userEmail}
                onChange={(e) => setUserEmail(e.target.value)}
              />
              <Input
                placeholder="Role (no validation)"
                value={userRole}
                onChange={(e) => setUserRole(e.target.value)}
              />
              <Button onClick={addUser}>
                <UserPlus className="h-4 w-4 mr-2" />
                Add User
              </Button>
            </div>
          </Card>

          <Card className="p-6">
            <h3 className="text-xl font-bold mb-4">User Database (Exposed PII)</h3>
            <div className="space-y-4">
              {users.map((user) => (
                <div key={user.id} className="flex items-center justify-between p-4 bg-secondary rounded-lg">
                  <div className="flex-1">
                    <p className="font-medium">{user.email}</p>
                    <p className="text-sm text-muted-foreground">Role: {user.role}</p>
                    <p className="text-sm text-destructive">SSN: {user.ssn}</p>
                    <p className="text-sm text-destructive">Credit Card: {user.creditCard}</p>
                  </div>
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={() => deleteUser(user.id)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
            </div>
          </Card>

          <Card className="p-6 bg-destructive/10 border-destructive">
            <h3 className="text-xl font-bold mb-2 text-destructive">Exposed Secrets</h3>
            <p className="text-sm mb-4">These should NEVER be in source code:</p>
            <div className="space-y-2 font-mono text-sm">
              <p>Admin Password: {ADMIN_PASSWORD}</p>
              <p className="break-all">API Key: {ADMIN_API_KEY}</p>
              <p>Database URL: postgresql://admin:password123@db.example.com:5432/prod_db</p>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default AdminPanel;
