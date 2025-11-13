# Security Configuration Guide

## 🔐 Environment Variables in Lovable Cloud

This project uses **Lovable Cloud**, which automatically manages Supabase credentials.

### Understanding the `.env` File

**IMPORTANT**: In Lovable Cloud projects, the `.env` file is **auto-generated** and should **NOT be manually edited**:

```bash
# ❌ DO NOT manually edit or delete .env in Cloud projects
# ✅ It's automatically managed by the Lovable Cloud platform
```

### Is the Anon Key Really Safe?

**YES!** The Supabase anon (publishable) key visible in `.env` is designed to be public:

| Key Type | Client-Side? | Purpose | Security Model |
|----------|-------------|---------|----------------|
| **Anon Key** (publishable) | ✅ Yes | Client apps, browsers | Limited by RLS policies |
| **Service Role Key** | ❌ Never! | Server-only, bypasses RLS | Admin operations |

### Where Security Really Happens

```
┌─────────────────────────────────────┐
│  Client App (Browser)               │
│  - Has anon key (public, OK!)       │
│  - Makes API requests               │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│  Supabase Backend                   │
│  ┌───────────────────────────────┐  │
│  │ Row Level Security (RLS)      │  │ ← REAL SECURITY HERE
│  │ - Checks auth.uid()          │  │
│  │ - Validates user roles       │  │
│  │ - Enforces access rules      │  │
│  └───────────────────────────────┘  │
│                                     │
│  ┌───────────────────────────────┐  │
│  │ PostgreSQL Database          │  │
│  │ - Only returns allowed rows  │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

## 🛡️ Security Hardening Applied

This project includes multiple security layers:

### 1. Runtime Environment Validation

The `src/lib/safeEnv.ts` module validates configuration at startup:

```typescript
// ✓ Checks environment variables are set
// ✓ Validates JWT structure of anon key  
// ✓ Prevents service_role key in client code
// ✓ Fails fast on misconfiguration
```

### 2. Secret Scanning (Pre-Commit Hooks)

Automatic scanning before every commit:

```bash
# Runs automatically on git commit
git commit -m "My changes"
# → Secretlint scans staged files
# → Blocks commit if secrets detected
```

Manual scan:
```bash
npm run scan:secrets
# or
npx secretlint "**/*"
```

### 3. Access Control Guards

Frontend components are protected:

```typescript
// AdminPanel requires authentication AND admin role
<RequireAuth>
  <RequireRole roles={["admin"]}>
    <AdminPanel />
  </RequireRole>
</RequireAuth>
```

### 4. Backend Security (Edge Functions)

All edge functions implement:

- ✅ CORS validation with allowlist (no `*` wildcards)
- ✅ MFA/step-up authentication for admin operations
- ✅ Authorization header validation (no cookie injection)
- ✅ Rate limiting and request size limits
- ✅ Input sanitization (no CRLF/control characters)

## 🚨 Common Security Mistakes to Avoid

### ❌ Mistake 1: Overly Permissive RLS

```sql
-- BAD: Allows anyone to see everything
CREATE POLICY "allow_all" ON profiles
  FOR SELECT USING (true);
```

✅ **Fix**: Implement least-privilege policies

```sql
-- GOOD: Users see only their own data
CREATE POLICY "users_own_data" ON profiles
  FOR SELECT USING (auth.uid() = user_id);

-- GOOD: Admins see everything via role check
CREATE POLICY "admins_all_data" ON profiles
  FOR SELECT USING (public.has_role(auth.uid(), 'admin'));
```

### ❌ Mistake 2: Forgetting to Enable RLS

```sql
-- BAD: RLS not enabled = full public access!
CREATE TABLE sensitive_data (
  id uuid PRIMARY KEY,
  user_id uuid,
  secret_info text
);
```

✅ **Fix**: Always enable RLS on sensitive tables

```sql
-- GOOD: RLS enabled first
ALTER TABLE sensitive_data ENABLE ROW LEVEL SECURITY;

-- Then add policies
CREATE POLICY "restrict_access" ON sensitive_data
  FOR ALL USING (auth.uid() = user_id);
```

### ❌ Mistake 3: Using Service Role Key Client-Side

```typescript
// ❌ CRITICAL SECURITY VULNERABILITY
const supabase = createClient(
  url,
  'service_role_key_here'  // NEVER do this!
);
```

✅ **Fix**: Always use anon key in client

```typescript
// ✅ Safe: Uses anon key (limited by RLS)
const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY
);
```

## 📋 Security Checklist

Before deploying or sharing your project:

### Database Security
- [ ] RLS is enabled on all tables with sensitive data
- [ ] Each table has appropriate SELECT/INSERT/UPDATE/DELETE policies
- [ ] Policies use `auth.uid()` to enforce user-level isolation
- [ ] Role-based policies use `has_role()` function
- [ ] No tables have `USING (true)` policies unless intentionally public
- [ ] Storage buckets have matching access policies

### Authentication & Authorization  
- [ ] Admin routes protected with MFA/step-up authentication
- [ ] Frontend admin UI guarded with RequireAuth + RequireRole
- [ ] No client-side admin checks (localStorage, hardcoded flags)
- [ ] Session management uses HttpOnly cookies (not localStorage)

### API Security
- [ ] Edge functions validate Authorization headers
- [ ] CORS configured with allowlist (no wildcard origins)
- [ ] Rate limiting enabled on public endpoints
- [ ] Input validation prevents injection attacks
- [ ] No control characters (CRLF) accepted in headers

### Code Security
- [ ] No service_role keys in client code
- [ ] No hardcoded credentials anywhere
- [ ] Environment variables validated at runtime
- [ ] Pre-commit hooks scan for secrets
- [ ] .gitignore blocks .env.local and similar files

## 🔄 Key Rotation Procedure

If you suspect the anon key has been compromised:

### 1. Audit Current Access

```bash
# Check Supabase logs for unusual activity
# Look for:
# - Unusual API patterns
# - Failed authentication attempts  
# - Unexpected data access
```

### 2. Review RLS Policies

```sql
-- List all tables and their RLS status
SELECT schemaname, tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'public';

-- View policies for a specific table
SELECT * FROM pg_policies
WHERE tablename = 'your_table_name';
```

### 3. Rotate the Anon Key (Lovable Cloud)

For Lovable Cloud projects, the platform manages keys automatically. If you need to rotate:

1. Contact Lovable support or use the Cloud dashboard
2. The new key will be automatically updated in `.env`
3. Redeploy your application

### 4. Tighten Policies

Review and update any overly permissive RLS policies:

```sql
-- Example: Add additional constraints
DROP POLICY IF EXISTS "old_policy" ON table_name;

CREATE POLICY "stricter_policy" ON table_name
  FOR SELECT USING (
    auth.uid() = user_id 
    AND status = 'active'  -- Additional check
  );
```

## 🔗 Additional Resources

- [Supabase RLS Guide](https://supabase.com/docs/guides/auth/row-level-security)
- [Lovable Security Docs](https://docs.lovable.dev/features/security)
- [OWASP API Security](https://owasp.org/www-project-api-security/)
- [Secretlint Rules](https://github.com/secretlint/secretlint)

## 📞 Reporting Security Issues

If you discover a security vulnerability:

1. **DO NOT** create a public GitHub issue
2. Email security concerns to project maintainers
3. Include steps to reproduce (if applicable)
4. Allow time for a fix before public disclosure

---

**Remember**: Security is a process, not a one-time task. Regularly review and update your security posture as your application grows.
