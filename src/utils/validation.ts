/**
 * Input Validation Utilities
 * 
 * Provides secure validation and sanitization for user inputs:
 * - Email format validation (RFC-5322-lite)
 * - PAN (Primary Account Number) detection with Luhn check
 * - Sensitive data redaction
 * 
 * SECURITY: These validators prevent data poisoning and PCI-DSS scope creep
 * by blocking PAN-like inputs in non-payment contexts.
 */

/**
 * Validate email format using conservative regex
 * Compliant with RFC-5322-lite pattern
 */
export function validateEmail(email: string): boolean {
  if (!email || email.length === 0) {
    return false;
  }
  
  // Conservative email pattern: localpart@domain.tld
  // Enforces: non-empty local and domain parts, valid TLD (2+ chars)
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  
  // Additional checks
  if (email.length > 254) return false; // RFC-5321 max length
  if (!emailRegex.test(email)) return false;
  
  // Reject obvious malformed patterns
  if (email.includes('..')) return false; // consecutive dots
  if (email.startsWith('.') || email.endsWith('.')) return false;
  if (email.includes('@.') || email.includes('.@')) return false;
  
  return true;
}

/**
 * Extract only numeric digits from a string
 */
export function extractDigits(str: string): string {
  return str.replace(/\D/g, '');
}

/**
 * Luhn algorithm check for card number validation
 * Used to detect PAN-like sequences
 */
export function luhnCheck(digits: string): boolean {
  if (!digits || digits.length < 13 || digits.length > 19) {
    return false;
  }
  
  const arr = digits.split('').reverse().map(Number);
  let sum = 0;
  
  for (let i = 0; i < arr.length; i++) {
    let digit = arr[i];
    
    // Double every second digit (odd indices in reversed array)
    if (i % 2 === 1) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    
    sum += digit;
  }
  
  return sum % 10 === 0;
}

/**
 * Detect if input looks like a PAN (Primary Account Number)
 * Uses digit count (13-19) and Luhn algorithm
 */
export function looksLikePAN(input: string): boolean {
  const digits = extractDigits(input);
  
  // PAN length is 13-19 digits (ISO/IEC 7812)
  if (digits.length < 13 || digits.length > 19) {
    return false;
  }
  
  // Apply Luhn check
  return luhnCheck(digits);
}

/**
 * Redact PAN-like sequences for safe display
 * Shows only last 4 digits, masks the rest
 */
export function redactPANForDisplay(input: string): string {
  const digits = extractDigits(input);
  
  if (digits.length < 13 || digits.length > 19) {
    // Not PAN-like, return as-is (but sanitized)
    return input;
  }
  
  // Mask all but last 4 digits
  const last4 = digits.slice(-4);
  const maskedCount = digits.length - 4;
  const masked = '*'.repeat(maskedCount);
  
  // Format as groups of 4 for readability
  const full = masked + last4;
  const groups = full.match(/.{1,4}/g) || [];
  
  return groups.join(' ');
}

/**
 * Sanitize credit card field input
 * Removes PAN-like data and returns safe representation
 * 
 * @returns Object with sanitized value and warning if PAN detected
 */
export function sanitizeCreditCardInput(input: string): {
  sanitized: string;
  isPANDetected: boolean;
  displayValue: string;
} {
  const trimmed = input.trim();
  
  if (looksLikePAN(trimmed)) {
    // PAN detected - redact and warn
    return {
      sanitized: '',
      isPANDetected: true,
      displayValue: redactPANForDisplay(trimmed),
    };
  }
  
  // Not a PAN - allow but limit length
  const maxLength = 50;
  const sanitized = trimmed.slice(0, maxLength);
  
  return {
    sanitized,
    isPANDetected: false,
    displayValue: sanitized,
  };
}
