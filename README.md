# Metal Prices & Security Demo

A React application demonstrating secure authentication patterns and metal price tracking, built with Lovable.

## 🔐 Security Features

This project implements multiple layers of security to protect against common web vulnerabilities:

### 1. **CSRF Protection** (Cross-Site Request Forgery)
- Double-submit cookie pattern on logout endpoint
- Origin and Referer validation
- POST-only state-changing operations
- Custom headers (X-CSRF-Token) required for authentication

### 2. **XSS Prevention** (Cross-Site Scripting)
- In-memory session storage (no localStorage exposure)
- Input validation using Zod schemas
- No `dangerouslySetInnerHTML` usage
- Content Security Policy ready

### 3. **Credential Protection**
- Runtime environment validation (`src/lib/safeEnv.ts`)
- Automated secret scanning (`npm run scan:secrets`)
- Service role key detection and rejection
- Secure session management

### 4. **Rate Limiting** (Recommended)
- Edge function rate limiting on auth endpoints
- IP-based attempt tracking
- Progressive backoff on failed attempts

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ or Bun
- Lovable Cloud account (auto-manages Supabase backend)

### Installation

```bash
# Install dependencies
npm install
# or
bun install

# Run development server
npm run dev
# or
bun dev
```

The app will be available at `http://localhost:8080`

## 📁 Project Structure

```
├── src/
│   ├── components/          # React components
│   ├── pages/              # Page components
│   ├── hooks/              # Custom React hooks
│   ├── lib/
│   │   ├── safeEnv.ts      # 🔐 Environment validation
│   │   └── utils.ts        # Utility functions
│   ├── integrations/
│   │   └── supabase/       # Supabase client (auto-generated)
│   └── utils/              # Validation & utilities
├── supabase/
│   └── functions/          # Edge functions (auth, admin checks)
└── scripts/
    └── scan-secrets.js     # 🔐 Secret scanner
```

## 🔒 Environment Variables & Security

### For Lovable Cloud (Default)

This project uses **Lovable Cloud**, which auto-manages your Supabase backend:

- The `.env` file is **auto-generated and auto-updated** by Lovable
- Contains real credentials but is **excluded from secret scanning**
- Runtime validation ensures only anon keys are used client-side
- **No manual setup required** - just start coding!

### For Self-Hosted or Custom Deployment

If you're self-hosting or using a custom Supabase project:

1. Copy `.env.example` to `.env.local`:
   ```bash
   cp .env.example .env.local
   ```

2. Fill in your Supabase credentials:
   ```bash
   VITE_SUPABASE_PROJECT_ID="your-project-ref"
   VITE_SUPABASE_URL="https://your-project-ref.supabase.co"
   VITE_SUPABASE_PUBLISHABLE_KEY="your-anon-key"
   ```

3. **Never commit `.env` or `.env.local`** to version control

### Security Notes

- The Supabase anon/publishable key is safe to expose in client-side code
- It's protected by Row Level Security (RLS) policies in your database
- Always review and test your RLS policies before deploying
- This project includes runtime environment validation (`src/lib/safeEnv.ts`)
- Secure session management uses in-memory storage to prevent XSS attacks

### Key Rotation

If you suspect your anon key has been compromised:

1. **Lovable Cloud**: Keys are managed automatically by the platform
2. **Self-hosted**: 
   - Go to your Supabase dashboard → Settings → API
   - Generate a new anon key
   - Update your `.env.local` file
   - Review and audit your RLS policies

## 🧪 Testing

### Run All Tests
```bash
npm test
```

### Security Tests
```bash
# Scan repository for accidentally committed secrets
npm run scan:secrets

# Test environment variable validation
npm run test:env

# Run both security checks
npm run test:security
```

### What Gets Scanned?

The secret scanner checks for:
- ✅ Supabase JWT tokens (anon/service_role)
- ✅ Supabase project URLs and references
- ✅ Common credential patterns

**Note:** The scanner ignores:
- `.env` (auto-managed by Lovable Cloud)
- `.env.example` (contains placeholders only)
- Test files with synthetic tokens
- `node_modules`, `dist`, `.git`

## 🏗️ Build & Deploy

### Development Build
```bash
npm run build:dev
```

### Production Build
```bash
npm run build
```

### Deploy with Lovable

1. Click **Publish** in the top-right corner
2. Click **Update** to deploy frontend changes
3. Backend changes (edge functions, migrations) deploy automatically

### Self-Hosted Deployment

Build the project and deploy the `dist/` folder to any static hosting:
- Vercel
- Netlify
- GitHub Pages
- Cloudflare Pages

Make sure to set environment variables in your hosting provider's dashboard.

## 🛡️ Security Checklist

Before deploying to production:

- [ ] Reviewed all RLS policies in Supabase
- [ ] Tested authentication flows (signup, login, logout)
- [ ] Ran `npm run test:security` with 0 findings
- [ ] Enabled rate limiting on auth endpoints
- [ ] Configured CORS for production domains only
- [ ] Reviewed edge function security (CSRF, origin validation)
- [ ] Tested with different user roles and permissions
- [ ] Verified no sensitive data logged to console
- [ ] Set up monitoring and alerts for auth failures

## 📚 Key Files for Security Review

- `src/lib/safeEnv.ts` - Environment validation & service role detection
- `supabase/functions/auth-login/index.ts` - Login with rate limiting
- `supabase/functions/auth-logout/index.ts` - CSRF-protected logout
- `supabase/functions/auth-signup/index.ts` - Signup with validation
- `scripts/scan-secrets.js` - Repository secret scanner
- `src/lib/safeEnv.test.ts` - Security test suite

## 🐛 Troubleshooting

### "Invalid authentication configuration" Error

This means environment variables are missing or invalid. Check:
1. `.env` exists (Lovable Cloud) or `.env.local` (self-hosted)
2. All three variables are set: `VITE_SUPABASE_URL`, `VITE_SUPABASE_PUBLISHABLE_KEY`, `VITE_SUPABASE_PROJECT_ID`
3. Values are not placeholders like `YOUR_PROJECT_REF`

### "Service role key detected" Error

This is a **critical security error**. You've accidentally included a service role key in client code:
1. Service role keys must **never** be in `VITE_*` variables
2. Use only the **anon/publishable** key for client-side code
3. Service role keys belong in edge functions with `Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')`

### Session Lost on Page Reload

This is expected behavior due to in-memory session storage (XSS protection):
- Sessions don't persist across page reloads
- Users must re-authenticate after refresh
- For production, consider implementing backend session management with HttpOnly cookies

## 📖 Learn More

- [Lovable Documentation](https://docs.lovable.dev)
- [Supabase Row Level Security](https://supabase.com/docs/guides/auth/row-level-security)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Web Security Best Practices](https://developer.mozilla.org/en-US/docs/Web/Security)

## How can I edit this code?

There are several ways of editing your application.

**Use Lovable**

Simply visit the [Lovable Project](https://lovable.dev/projects/59ca1c9e-f6b1-49a0-b1b0-d6ca146ba837) and start prompting.

Changes made via Lovable will be committed automatically to this repo.

**Use your preferred IDE**

If you want to work locally using your own IDE, you can clone this repo and push changes. Pushed changes will also be reflected in Lovable.

The only requirement is having Node.js & npm installed - [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating)

Follow these steps:

```sh
# Step 1: Clone the repository using the project's Git URL.
git clone <YOUR_GIT_URL>

# Step 2: Navigate to the project directory.
cd <YOUR_PROJECT_NAME>

# Step 3: Install the necessary dependencies.
npm i

# Step 4: Start the development server with auto-reloading and an instant preview.
npm run dev
```

## What technologies are used for this project?

This project is built with:

- Vite
- TypeScript
- React
- shadcn-ui
- Tailwind CSS

## Can I connect a custom domain to my Lovable project?

Yes, you can!

To connect a domain, navigate to Project > Settings > Domains and click Connect Domain.

Read more here: [Setting up a custom domain](https://docs.lovable.dev/features/custom-domain#custom-domain)

---

**⚠️ Security Notice:** This is a demonstration project. Always conduct a thorough security audit before deploying to production. Review RLS policies, test edge cases, and implement additional security measures as needed for your specific use case.
