# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it by emailing the project maintainers. Do not create a public GitHub issue for security vulnerabilities.

## Environment Variables and Secrets

### Lovable Cloud Projects (This Project)

This project uses **Lovable Cloud**, where Supabase credentials are automatically managed:

- **`.env` file**: Auto-generated and updated by the Cloud platform
- **Supabase anon key**: This is a **publishable key** designed for client-side use
- **Real security**: Implemented through Row Level Security (RLS) policies, not by hiding the anon key

### Security Model

The Supabase anon (publishable) key visible in `.env` is **intentionally public**:

1. ✅ **Safe to embed in client code** - It's designed for browser/mobile apps
2. ✅ **Limited by RLS policies** - Database access is controlled by PostgreSQL Row Level Security
3. ✅ **Cannot perform admin operations** - Only the service_role key (never exposed) can bypass RLS
4. ❌ **Service role key** - Never exposed client-side, kept in secure server environment

### What Makes This Secure?

Security in Supabase apps comes from **multiple layers**:

1. **Row Level Security (RLS) Policies** - PostgreSQL policies control who can read/write data
2. **Authentication** - Users must authenticate to access protected resources  
3. **Authorization** - RLS policies check user roles/ownership before allowing access
4. **API Rate Limiting** - Prevents abuse even with public anon key
5. **Storage Policies** - Control file upload/download permissions

### Key Rotation

If you suspect the anon key has been compromised or used maliciously:

1. **Audit RLS policies** - Ensure all tables have proper RLS enabled
2. **Review access logs** - Check for unusual API usage patterns
3. **Rotate the key** - Generate new anon key in Supabase dashboard if needed
4. **Update policies** - Tighten any overly permissive RLS rules

### Development Setup (Non-Cloud Projects)

For projects not using Lovable Cloud:

1. Copy `.env.example` to `.env.local`
2. Never commit `.env.local` (already in `.gitignore`)
3. Get credentials from Supabase dashboard
4. Use the **anon key** for client code, never service_role

## Pre-Commit Secret Scanning

This project uses **Secretlint** to prevent accidental secret commits:

```bash
# Automatically runs on git commit
# To manually scan:
npx secretlint "**/*"
```

## Security Checklist for RLS

Ensure Row Level Security is properly configured:

- [ ] RLS is **enabled** on all tables (`ALTER TABLE ... ENABLE ROW LEVEL SECURITY`)
- [ ] Tables have appropriate policies for SELECT, INSERT, UPDATE, DELETE
- [ ] Policies check `auth.uid()` to enforce user-level access
- [ ] Role-based policies use the `has_role()` function correctly
- [ ] No tables allow anonymous access unless explicitly intended
- [ ] Storage buckets have policies matching table access patterns
- [ ] Public data is explicitly allowed with documented reasoning

## Common Security Pitfalls

### ❌ DON'T DO THIS:

```sql
-- Overly permissive policy allowing anyone to read everything
CREATE POLICY "public_read" ON profiles FOR SELECT USING (true);

-- Missing RLS on sensitive table
-- (RLS not enabled = full public access with anon key!)
```

### ✅ DO THIS INSTEAD:

```sql
-- Enable RLS
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

-- Users can only read their own profile
CREATE POLICY "Users can view own profile" ON profiles
  FOR SELECT USING (auth.uid() = user_id);

-- Admins can read all profiles  
CREATE POLICY "Admins can view all profiles" ON profiles
  FOR SELECT USING (public.has_role(auth.uid(), 'admin'));
```

## Additional Resources

- [Supabase RLS Documentation](https://supabase.com/docs/guides/auth/row-level-security)
- [Lovable Security Best Practices](https://docs.lovable.dev/features/security)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

## Audit Trail

### Recent Security Improvements

- **2025-01**: Added Secretlint pre-commit hooks to prevent secret leaks
- **2025-01**: Added runtime validation for environment variables
- **2025-01**: Implemented MFA/step-up authentication for admin endpoints
- **2025-01**: Fixed header injection vulnerability in auth-logout
- **2025-01**: Fixed CORS misconfiguration in auth-session
- **2025-01**: Implemented access control guards for AdminPanel
