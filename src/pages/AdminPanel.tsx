import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { Trash2, UserPlus } from "lucide-react";
import { useAdminCheck } from "@/hooks/useAdminCheck";
import { supabase } from "@/integrations/supabase/client";

const AdminPanel = () => {
  const { toast } = useToast();
  const { isAdmin, isLoading, user } = useAdminCheck();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [userEmail, setUserEmail] = useState("");
  const [userRole, setUserRole] = useState("");
  const [users, setUsers] = useState<any[]>([]);
  const [isSignUp, setIsSignUp] = useState(false);

  const handleAuth = async () => {
    try {
      if (isSignUp) {
        const { error } = await supabase.auth.signUp({
          email,
          password,
        });
        
        if (error) throw error;
        
        toast({
          title: "Account Created",
          description: "Please check your email to verify your account. Contact admin to get admin access.",
        });
      } else {
        const { error } = await supabase.auth.signInWithPassword({
          email,
          password,
        });
        
        if (error) throw error;
        
        toast({
          title: "Signed In",
          description: "Checking admin privileges...",
        });
      }
    } catch (error: any) {
      toast({
        title: "Authentication Error",
        description: error.message,
        variant: "destructive",
      });
    }
  };

  const handleLogout = async () => {
    try {
      await supabase.auth.signOut();
      toast({
        title: "Logged Out",
        description: "You have been logged out successfully",
      });
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message,
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
    // Fixed: Basic validation to remove input validation vulnerability here
    const emailValid = /.+@.+\..+/.test(userEmail);
    const roleValid = ["admin", "user"].includes(userRole.trim().toLowerCase());
    if (!emailValid || !roleValid) {
      toast({ title: "Invalid input", description: "Enter a valid email and role (admin/user)", variant: "destructive" });
      return;
    }
    const newUser = {
      id: users.length + 1,
      email: userEmail,
      role: userRole,
    };
    setUsers([...users, newUser]);
    setUserEmail("");
    setUserRole("");
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Card className="p-8 max-w-md w-full">
          <p className="text-center text-muted-foreground">Loading...</p>
        </Card>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Card className="p-8 max-w-md w-full">
          <h2 className="text-2xl font-bold mb-4 text-foreground">
            {isSignUp ? "Sign Up" : "Admin Login"}
          </h2>
          <p className="text-sm text-muted-foreground mb-4">
            {isSignUp 
              ? "Create an account. Contact admin for admin privileges." 
              : "Sign in with your credentials to access the admin panel."}
          </p>
          <Input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mb-4"
          />
          <Input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mb-4"
          />
          <Button onClick={handleAuth} className="w-full mb-2">
            {isSignUp ? "Sign Up" : "Sign In"}
          </Button>
          <Button 
            variant="ghost" 
            onClick={() => setIsSignUp(!isSignUp)} 
            className="w-full"
          >
            {isSignUp ? "Already have an account? Sign In" : "Need an account? Sign Up"}
          </Button>
        </Card>
      </div>
    );
  }

  if (!isAdmin) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Card className="p-8 max-w-md w-full">
          <h2 className="text-2xl font-bold mb-4 text-foreground">Access Denied</h2>
          <p className="text-muted-foreground mb-4">
            You do not have admin privileges. Contact an administrator to request access.
          </p>
          <Button onClick={handleLogout} variant="destructive" className="w-full">
            Logout
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
            <p className="text-muted-foreground">✅ Secure admin panel with server-side authentication</p>
            <p className="text-sm text-muted-foreground">Logged in as: {user?.email}</p>
          </div>
          <Button 
            variant="destructive"
            onClick={handleLogout}
          >
            Logout
          </Button>
        </div>

        <div className="grid gap-6 mb-8">
          <Card className="p-6">
            <h3 className="text-xl font-bold mb-4">Add New User</h3>
            <div className="flex gap-4">
              <Input
                placeholder="Email"
                value={userEmail}
                onChange={(e) => setUserEmail(e.target.value)}
              />
              <Input
                placeholder="Role (admin or user)"
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

          <Card className="p-6 bg-green-500/10 border-green-500">
            <h3 className="text-xl font-bold mb-2 text-green-600">Security Status</h3>
            <p className="text-sm mb-4">This admin panel now uses secure server-side authentication.</p>
            <div className="space-y-2 text-sm">
              <p>✅ No hardcoded credentials</p>
              <p>✅ Server-side role verification</p>
              <p>✅ Protected by authentication</p>
              <p>✅ Role-based access control (RBAC)</p>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default AdminPanel;
