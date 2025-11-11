import { COMMON_PASSWORDS } from './common-passwords.ts';

/**
 * Password Policy Module
 * 
 * Implements NIST-aligned password requirements:
 * - Minimum 12 characters (or 20+ for passphrases)
 * - Character complexity OR passphrase structure
 * - Unicode normalization (NFKC)
 * - Common password rejection
 * - Pattern detection (repeated chars, sequences)
 * 
 * SECURITY: No passwords are logged. All validation is local (no network calls).
 */

export interface PasswordValidationResult {
  ok: boolean;
  message?: string;
  codes?: string[];
}

const MIN_LENGTH = 12;
const MAX_LENGTH = 128;
const PASSPHRASE_MIN_LENGTH = 20;
const MIN_COMPLEXITY_CLASSES = 3;

/**
 * Normalize password for validation and storage
 * - Applies Unicode NFKC normalization
 * - Trims leading/trailing whitespace
 * - Removes zero-width and control characters
 * - Collapses internal whitespace to single spaces
 */
export function normalizePassword(password: string): string {
  if (!password) return '';
  
  // Apply Unicode normalization (NFKC) for consistency
  let normalized = password.normalize('NFKC');
  
  // Trim leading/trailing whitespace
  normalized = normalized.trim();
  
  // Remove zero-width and control characters
  // \u200B = zero-width space
  // \u200C = zero-width non-joiner
  // \u200D = zero-width joiner
  // \uFEFF = zero-width no-break space (BOM)
  // \u00AD = soft hyphen
  normalized = normalized.replace(/[\u200B\u200C\u200D\uFEFF\u00AD]/g, '');
  
  // Remove other control characters (except normal space and newlines for passphrases)
  // eslint-disable-next-line no-control-regex
  normalized = normalized.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, '');
  
  // Collapse multiple internal spaces to single space (for passphrase word detection)
  normalized = normalized.replace(/\s+/g, ' ');
  
  return normalized;
}

/**
 * Check if password contains a repeated character pattern
 */
function hasRepeatedChars(password: string): boolean {
  if (password.length < 12) return false;
  
  // Check if entire password is a single character repeated
  const firstChar = password[0];
  return password.split('').every(char => char === firstChar);
}

/**
 * Check if password contains simple ascending or descending sequences
 */
function hasSimpleSequence(password: string): boolean {
  const sequences = [
    // Numeric sequences
    '0123456789',
    '9876543210',
    '01234567890',
    '09876543210',
    
    // Alphabetic sequences (lowercase)
    'abcdefghijklmnopqrstuvwxyz',
    'zyxwvutsrqponmlkjihgfedcba',
    
    // Alphabetic sequences (uppercase)
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'ZYXWVUTSRQPONMLKJIHGFEDCBA',
    
    // Common keyboard patterns
    'qwertyuiop',
    'asdfghjkl',
    'zxcvbnm',
    'qwerty',
    'asdfgh',
    'zxcvb',
    'poiuyt',
    'lkjhgf',
    'mnbvcx',
  ];
  
  const lowerPassword = password.toLowerCase();
  
  // Check if password contains any sequence of 6+ characters
  for (const seq of sequences) {
    for (let i = 0; i <= seq.length - 6; i++) {
      const substring = seq.substring(i, i + 6);
      if (lowerPassword.includes(substring)) {
        return true;
      }
    }
  }
  
  return false;
}

/**
 * Count character class diversity
 */
function countCharacterClasses(password: string): number {
  let classes = 0;
  
  // Lowercase letters
  if (/[a-z]/.test(password)) classes++;
  
  // Uppercase letters
  if (/[A-Z]/.test(password)) classes++;
  
  // Digits
  if (/[0-9]/.test(password)) classes++;
  
  // Symbols (anything that's not letter, number, or whitespace)
  // Using Unicode-aware pattern
  if (/[^\p{L}\p{N}\s]/u.test(password)) classes++;
  
  return classes;
}

/**
 * Check if password qualifies as a valid passphrase
 * Requirements:
 * - At least 20 characters
 * - At least 2 distinct words (separated by spaces)
 * - Not composed of a single word repeated
 */
function isValidPassphrase(password: string): boolean {
  if (password.length < PASSPHRASE_MIN_LENGTH) return false;
  
  // Must contain at least one space
  if (!password.includes(' ')) return false;
  
  // Split into words
  const words = password.split(' ').filter(w => w.length > 0);
  
  // Must have at least 2 words
  if (words.length < 2) return false;
  
  // Check that not all words are identical
  const uniqueWords = new Set(words.map(w => w.toLowerCase()));
  if (uniqueWords.size === 1) return false; // Single word repeated
  
  return true;
}

/**
 * Check if password is in common password denylist
 */
function isCommonPassword(password: string): boolean {
  // Normalize for comparison: lowercase and remove all spaces
  const normalized = password.toLowerCase().replace(/\s/g, '');
  
  return COMMON_PASSWORDS.has(normalized);
}

/**
 * Validate password against security policy
 * 
 * @param password - Normalized password to validate
 * @returns Validation result with ok status, message, and error codes
 */
export function validatePassword(password: string): PasswordValidationResult {
  const codes: string[] = [];
  
  // Check if empty
  if (!password || password.length === 0) {
    return {
      ok: false,
      message: 'Password is required.',
      codes: ['required'],
    };
  }
  
  // Check maximum length (prevent resource abuse)
  if (password.length > MAX_LENGTH) {
    return {
      ok: false,
      message: `Password must not exceed ${MAX_LENGTH} characters.`,
      codes: ['too_long'],
    };
  }
  
  // Check minimum length
  if (password.length < MIN_LENGTH) {
    codes.push('min_length');
  }
  
  // Check for common passwords
  if (isCommonPassword(password)) {
    return {
      ok: false,
      message: 'This password is too common and has been compromised in data breaches. Please choose a different password.',
      codes: ['weak_common'],
    };
  }
  
  // Check for repeated characters
  if (hasRepeatedChars(password)) {
    return {
      ok: false,
      message: 'Password cannot consist of repeated characters.',
      codes: ['repeated_chars'],
    };
  }
  
  // Check for simple sequences
  if (hasSimpleSequence(password)) {
    return {
      ok: false,
      message: 'Password cannot contain simple sequences or keyboard patterns.',
      codes: ['simple_sequence'],
    };
  }
  
  // Check if it's a valid passphrase (alternative to complexity requirements)
  const isPassphrase = isValidPassphrase(password);
  
  if (isPassphrase) {
    // Passphrase is valid, no need to check complexity
    return { ok: true };
  }
  
  // Not a valid passphrase, check character complexity
  const charClasses = countCharacterClasses(password);
  
  if (charClasses < MIN_COMPLEXITY_CLASSES) {
    codes.push('low_complexity');
  }
  
  // If we have any error codes, reject
  if (codes.length > 0) {
    let message = `Password must be at least ${MIN_LENGTH} characters and include at least ${MIN_COMPLEXITY_CLASSES} of: lowercase, uppercase, number, symbol.`;
    message += ` Alternatively, use a passphrase of ${PASSPHRASE_MIN_LENGTH}+ characters with multiple words.`;
    
    return {
      ok: false,
      message,
      codes,
    };
  }
  
  return { ok: true };
}
