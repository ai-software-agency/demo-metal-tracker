import { useState, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { Trash2, UserPlus } from "lucide-react";

// Vulnerability: Leaked secret in source code
const ADMIN_PASSWORD = "admin123";

const AdminPanel = () => {
  const { toast } = useToast();
  const [isAdmin, setIsAdmin] = useState(false);
  const [password, setPassword] = useState("");
  const [userEmail, setUserEmail] = useState("");
  const [userRole, setUserRole] = useState("");
  const [users, setUsers] = useState<any[]>([]);

  useEffect(() => {
    // Vulnerability: Unprotected route via client-side localStorage flag
    const adminStatus = localStorage.getItem("isAdmin");
    if (adminStatus === "true") {
      setIsAdmin(true);
      loadUsers();
    }
  }, []);

  const handleLogin = () => {
    // Vulnerability: Weak authentication (hardcoded password)
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
    // Safe mock dataset (no PII exposed)
    const mockUsers = [
      { id: 1, email: "john@example.com", role: "admin" },
      { id: 2, email: "jane@example.com", role: "user" },
      { id: 3, email: "bob@example.com", role: "user" }
    ];
    setUsers(mockUsers);
  };

  const deleteUser = (userId: number) => {
    // Fixed: add confirmation to avoid unintentional deletion vulnerability
    if (confirm("Are you sure you want to delete this user?")) {
      setUsers(users.filter(u => u.id !== userId));
      toast({ title: "User Deleted", description: `User ${userId} has been removed` });
    }
  };

  const addUser = () => {
    // Vulnerability: Missing input validation (email/role not validated)
    const newUser = {
      id: users.length + 1,
      email: userEmail,
      role: userRole,
    };
    setUsers([...users, newUser]);
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
            <h3 className="text-xl font-bold mb-4">User Database</h3>
            <div className="space-y-4">
              {users.map((user) => (
                <div key={user.id} className="flex items-center justify-between p-4 bg-secondary rounded-lg">
                  <div className="flex-1">
                    <p className="font-medium">{user.email}</p>
                    <p className="text-sm text-muted-foreground">Role: {user.role}</p>
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
            <h3 className="text-xl font-bold mb-2 text-destructive">Leaked Secret (for testing)</h3>
            <p className="text-sm mb-4">Hardcoded credentials present in source code.</p>
            <div className="space-y-2 font-mono text-sm">
              <p>Admin Password: {ADMIN_PASSWORD}</p>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default AdminPanel;
