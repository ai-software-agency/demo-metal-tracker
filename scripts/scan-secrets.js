#!/usr/bin/env node

/**
 * SECURITY: Repository Secrets Scanner
 * 
 * Scans the repository for accidentally committed secrets including:
 * - Supabase JWT tokens (anon/service_role keys)
 * - Supabase URLs with project references
 * - Other credential patterns
 * 
 * IMPORTANT: For Lovable Cloud projects:
 * - The .env file is auto-managed by Lovable and contains real credentials by design
 * - Runtime validation in src/lib/safeEnv.ts ensures only anon keys are used client-side
 * - This scanner ignores .env but checks all other files for accidental exposure
 * 
 * Usage: npm run scan:secrets
 * Returns exit code 1 if secrets are found, 0 otherwise
 */

import { readdirSync, readFileSync, statSync } from 'fs';
import { join } from 'path';

// Patterns to detect secrets (regex)
const SECRET_PATTERNS = [
  {
    name: 'Supabase JWT Token',
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    description: 'JWT token (potential Supabase anon or service_role key)',
  },
  {
    name: 'Supabase Project URL',
    pattern: /https:\/\/[a-z]{20}\.supabase\.co/g,
    description: 'Hardcoded Supabase project URL',
  },
  {
    name: 'Supabase Project Reference',
    pattern: /VITE_SUPABASE_PROJECT_ID=["']?[a-z]{20}["']?/g,
    description: 'Supabase project ID in environment variable',
  },
];

// Files and directories to ignore
const IGNORE_PATTERNS = [
  'node_modules',
  '.git',
  'dist',
  'dist-ssr',
  '.env',                // Lovable Cloud auto-managed - contains real values by design
  '.env.example',        // Explicitly allowed - contains placeholders
  'scan-secrets.js',     // This script itself
  'safeEnv.test.ts',     // Test files with synthetic tokens
  'safeEnv.test.js',
  '.gitignore',
  'package-lock.json',
  'bun.lockb',
];

// Allowed files that may contain example/test tokens
const ALLOWED_FILES = [
  '.env.example',
  'tests/safeEnv.test.ts',
  'src/lib/safeEnv.test.ts',
];

class SecretsScanner {
  constructor(rootDir) {
    this.rootDir = rootDir;
    this.findings = [];
  }

  shouldIgnore(path) {
    return IGNORE_PATTERNS.some(pattern => path.includes(pattern));
  }

  isAllowedFile(relativePath) {
    return ALLOWED_FILES.some(allowed => relativePath.endsWith(allowed));
  }

  scanFile(filePath, relativePath) {
    if (this.shouldIgnore(filePath)) {
      return;
    }

    try {
      const content = readFileSync(filePath, 'utf-8');
      
      for (const { name, pattern, description } of SECRET_PATTERNS) {
        const matches = content.match(pattern);
        
        if (matches && matches.length > 0) {
          // Check if this file is explicitly allowed
          if (this.isAllowedFile(relativePath)) {
            continue;
          }

          this.findings.push({
            file: relativePath,
            type: name,
            description,
            matches: matches.length,
            preview: matches[0].substring(0, 50) + '...',
          });
        }
      }
    } catch (error) {
      // Ignore binary files or read errors
      if (error.code !== 'ENOENT') {
        // Only log unexpected errors
      }
    }
  }

  scanDirectory(dirPath, relativePath = '') {
    if (this.shouldIgnore(dirPath)) {
      return;
    }

    try {
      const entries = readdirSync(dirPath);

      for (const entry of entries) {
        const fullPath = join(dirPath, entry);
        const relPath = relativePath ? join(relativePath, entry) : entry;

        if (this.shouldIgnore(fullPath)) {
          continue;
        }

        const stat = statSync(fullPath);

        if (stat.isDirectory()) {
          this.scanDirectory(fullPath, relPath);
        } else if (stat.isFile()) {
          this.scanFile(fullPath, relPath);
        }
      }
    } catch (error) {
      console.error(`Error scanning directory ${dirPath}:`, error.message);
    }
  }

  run() {
    console.log('🔍 Scanning repository for secrets...\n');
    this.scanDirectory(this.rootDir);
    return this.findings;
  }

  report() {
    if (this.findings.length === 0) {
      console.log('✅ No secrets detected in tracked files');
      console.log('ℹ️  Note: .env is auto-managed by Lovable Cloud and excluded from scanning\n');
      return 0;
    }

    console.error('❌ SECRETS DETECTED IN REPOSITORY\n');
    console.error(`Found ${this.findings.length} potential secret(s):\n`);

    for (const finding of this.findings) {
      console.error(`File: ${finding.file}`);
      console.error(`Type: ${finding.type}`);
      console.error(`Description: ${finding.description}`);
      console.error(`Matches: ${finding.matches}`);
      console.error(`Preview: ${finding.preview}`);
      console.error('---');
    }

    console.error('\n⚠️  ACTION REQUIRED:');
    console.error('1. Remove real credentials from tracked files');
    console.error('2. Use .env.example with placeholders instead');
    console.error('3. Ensure .env is in .gitignore');
    console.error('4. Rotate any exposed credentials immediately\n');

    return 1;
  }
}

// Run scanner
const scanner = new SecretsScanner(process.cwd());
scanner.run();
const exitCode = scanner.report();
process.exit(exitCode);
