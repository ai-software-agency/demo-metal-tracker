# Welcome to your Lovable project

## Project info

**URL**: https://lovable.dev/projects/59ca1c9e-f6b1-49a0-b1b0-d6ca146ba837

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

**Edit a file directly in GitHub**

- Navigate to the desired file(s).
- Click the "Edit" button (pencil icon) at the top right of the file view.
- Make your changes and commit the changes.

**Use GitHub Codespaces**

- Navigate to the main page of your repository.
- Click on the "Code" button (green button) near the top right.
- Select the "Codespaces" tab.
- Click on "New codespace" to launch a new Codespace environment.
- Edit files directly within the Codespace and commit and push your changes once you're done.

## What technologies are used for this project?

This project is built with:

- Vite
- TypeScript
- React
- shadcn-ui
- Tailwind CSS

## Environment Variables & Security

This project uses **Lovable Cloud**, which automatically manages backend configuration including Supabase credentials.

### For Lovable Cloud Projects (Current Setup)

- `.env` file is **auto-generated and managed** by Lovable Cloud
- Credentials are automatically provided in the Lovable development environment
- No manual configuration needed when using Lovable

### For Self-Hosted Deployments

If you're deploying outside of Lovable:

1. Copy `.env.example` to `.env` in your local environment
2. Replace placeholder values with your actual Supabase credentials:
   ```
   VITE_SUPABASE_PROJECT_ID="your-project-id"
   VITE_SUPABASE_PUBLISHABLE_KEY="your-anon-key"
   VITE_SUPABASE_URL="https://your-project.supabase.co"
   ```
3. **Never commit** `.env` to version control (it's in `.gitignore`)
4. For CI/CD, provide environment variables through your deployment platform

### Security Notes

- The Supabase anon/publishable key is safe to expose in client-side code
- It's protected by Row Level Security (RLS) policies in your database
- Always review and test your RLS policies before deploying
- This project includes runtime environment validation (`src/lib/safeEnv.ts`)
- Secure session management uses in-memory storage to prevent XSS attacks

### Optional: Secret Scanning

For additional security in production repositories, consider adding secret scanning:
- **TruffleHog** (free, open-source): [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog)
- **GitGuardian** (free tier available): [GitGuardian GitHub Action](https://github.com/GitGuardian/ggshield-action)
- **git-secrets** (free, AWS tool): [awslabs/git-secrets](https://github.com/awslabs/git-secrets)

### Key Rotation

If you need to rotate your Supabase keys:

1. **Lovable Cloud**: Managed automatically by the platform
2. **Self-hosted**: Generate new keys in your Supabase dashboard and update environment variables

## How can I deploy this project?

Simply open [Lovable](https://lovable.dev/projects/59ca1c9e-f6b1-49a0-b1b0-d6ca146ba837) and click on Share -> Publish.

## Can I connect a custom domain to my Lovable project?

Yes, you can!

To connect a domain, navigate to Project > Settings > Domains and click Connect Domain.

Read more here: [Setting up a custom domain](https://docs.lovable.dev/features/custom-domain#custom-domain)
