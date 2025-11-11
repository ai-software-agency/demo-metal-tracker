import { assertEquals } from "https://deno.land/std@0.192.0/testing/asserts.ts";
import { normalizePassword, validatePassword } from "./passwordPolicy.ts";

/**
 * Password Policy Test Suite
 * 
 * Covers:
 * - Common password rejection
 * - Repeated character detection
 * - Simple sequence detection
 * - Character complexity requirements
 * - Passphrase acceptance
 * - Normalization (NFKC, whitespace, zero-width chars)
 * - Edge cases (length limits, empty, special chars)
 */

// ============================================================================
// SECURITY REJECTION TESTS - Common Passwords
// ============================================================================

Deno.test("Security - Rejects common password: 123456", () => {
  const result = validatePassword(normalizePassword('123456'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('weak_common'), true);
});

Deno.test("Security - Rejects common password: password", () => {
  const result = validatePassword(normalizePassword('password'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('weak_common'), true);
});

Deno.test("Security - Rejects common password: qwerty", () => {
  const result = validatePassword(normalizePassword('qwerty'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('weak_common'), true);
});

Deno.test("Security - Rejects common password: password123", () => {
  const result = validatePassword(normalizePassword('password123'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('weak_common'), true);
});

Deno.test("Security - Rejects common password: admin (case insensitive)", () => {
  const result = validatePassword(normalizePassword('ADMIN'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('weak_common'), true);
});

Deno.test("Security - Rejects common password with spaces: pass word", () => {
  const result = validatePassword(normalizePassword('pass word'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('weak_common'), true);
});

// ============================================================================
// SECURITY REJECTION TESTS - Repeated Characters
// ============================================================================

Deno.test("Security - Rejects repeated characters: aaaaaaaaaaaa", () => {
  const result = validatePassword(normalizePassword('aaaaaaaaaaaa'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('repeated_chars'), true);
});

Deno.test("Security - Rejects repeated characters: 111111111111", () => {
  const result = validatePassword(normalizePassword('111111111111'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('repeated_chars'), true);
});

Deno.test("Security - Rejects repeated characters: XXXXXXXXXXXX", () => {
  const result = validatePassword(normalizePassword('XXXXXXXXXXXX'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('repeated_chars'), true);
});

// ============================================================================
// SECURITY REJECTION TESTS - Simple Sequences
// ============================================================================

Deno.test("Security - Rejects numeric sequence: 1234567890", () => {
  const result = validatePassword(normalizePassword('1234567890'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('simple_sequence'), true);
});

Deno.test("Security - Rejects alphabetic sequence: abcdefghij", () => {
  const result = validatePassword(normalizePassword('abcdefghij'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('simple_sequence'), true);
});

Deno.test("Security - Rejects keyboard pattern: qwertyuiop", () => {
  const result = validatePassword(normalizePassword('qwertyuiop'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('simple_sequence'), true);
});

Deno.test("Security - Rejects sequence with suffix: abcdefg123", () => {
  const result = validatePassword(normalizePassword('abcdefg123'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('simple_sequence'), true);
});

Deno.test("Security - Rejects reverse sequence: 9876543210", () => {
  const result = validatePassword(normalizePassword('9876543210'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('simple_sequence'), true);
});

// ============================================================================
// SECURITY REJECTION TESTS - Length & Complexity
// ============================================================================

Deno.test("Security - Rejects short password: Passw0rd!", () => {
  const result = validatePassword(normalizePassword('Passw0rd!'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('min_length'), true);
});

Deno.test("Security - Rejects low complexity: abcdefghijkl", () => {
  const result = validatePassword(normalizePassword('abcdefghijkl'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('low_complexity'), true);
});

Deno.test("Security - Rejects low complexity: ABCDEFGHIJKL", () => {
  const result = validatePassword(normalizePassword('ABCDEFGHIJKL'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('low_complexity'), true);
});

Deno.test("Security - Rejects low complexity: 123456789012", () => {
  const result = validatePassword(normalizePassword('123456789012'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('low_complexity'), true);
});

Deno.test("Security - Rejects password exceeding max length", () => {
  const longPassword = 'A'.repeat(129) + 'b1!';
  const result = validatePassword(normalizePassword(longPassword));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('too_long'), true);
});

// ============================================================================
// ACCEPTANCE TESTS - Strong Passwords
// ============================================================================

Deno.test("Acceptance - Accepts strong password: S7rong!EnoughPass", () => {
  const result = validatePassword(normalizePassword('S7rong!EnoughPass'));
  assertEquals(result.ok, true);
  assertEquals(result.codes, undefined);
});

Deno.test("Acceptance - Accepts strong password: MyP@ssw0rd2024!", () => {
  const result = validatePassword(normalizePassword('MyP@ssw0rd2024!'));
  assertEquals(result.ok, true);
});

Deno.test("Acceptance - Accepts strong password: Tr0ub4dor&3Extended", () => {
  const result = validatePassword(normalizePassword('Tr0ub4dor&3Extended'));
  assertEquals(result.ok, true);
});

Deno.test("Acceptance - Accepts password with 3 classes: MyPassword123", () => {
  const result = validatePassword(normalizePassword('MyPassword123'));
  assertEquals(result.ok, true);
});

Deno.test("Acceptance - Accepts password with symbols: lower-UPPER-123-!", () => {
  const result = validatePassword(normalizePassword('lower-UPPER-123-!'));
  assertEquals(result.ok, true);
});

// ============================================================================
// ACCEPTANCE TESTS - Passphrases
// ============================================================================

Deno.test("Acceptance - Accepts valid passphrase: correct horse battery staple", () => {
  const result = validatePassword(normalizePassword('correct horse battery staple'));
  assertEquals(result.ok, true);
});

Deno.test("Acceptance - Accepts passphrase: my super secret password phrase here", () => {
  const result = validatePassword(normalizePassword('my super secret password phrase here'));
  assertEquals(result.ok, true);
});

Deno.test("Acceptance - Accepts passphrase with minimal length: twenty character pass", () => {
  const result = validatePassword(normalizePassword('twenty character pass'));
  assertEquals(result.ok, true);
});

Deno.test("Security - Rejects passphrase with single repeated word", () => {
  const result = validatePassword(normalizePassword('word word word word word'));
  assertEquals(result.ok, false);
});

Deno.test("Security - Rejects passphrase too short: short phrase here", () => {
  const result = validatePassword(normalizePassword('short phrase here'));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('min_length'), true);
});

// ============================================================================
// ACCEPTANCE TESTS - International Characters
// ============================================================================

Deno.test("Acceptance - Accepts password with international chars: pässWÖRD-安全-密码123!", () => {
  const result = validatePassword(normalizePassword('pässWÖRD-安全-密码123!'));
  assertEquals(result.ok, true);
});

Deno.test("Acceptance - Accepts Cyrillic password: МойПароль2024!", () => {
  const result = validatePassword(normalizePassword('МойПароль2024!'));
  assertEquals(result.ok, true);
});

Deno.test("Acceptance - Accepts Arabic password: كلمةالسر123!ABC", () => {
  const result = validatePassword(normalizePassword('كلمةالسر123!ABC'));
  assertEquals(result.ok, true);
});

// ============================================================================
// NORMALIZATION TESTS
// ============================================================================

Deno.test("Normalization - Trims leading and trailing spaces", () => {
  const normalized = normalizePassword('  MyPassword123!  ');
  assertEquals(normalized, 'MyPassword123!');
  const result = validatePassword(normalized);
  assertEquals(result.ok, true);
});

Deno.test("Normalization - Removes zero-width characters", () => {
  // Password with zero-width space (\u200B)
  const passwordWithZeroWidth = 'MyPass\u200Bword123!';
  const normalized = normalizePassword(passwordWithZeroWidth);
  assertEquals(normalized, 'MyPassword123!');
  const result = validatePassword(normalized);
  assertEquals(result.ok, true);
});

Deno.test("Normalization - Removes multiple zero-width chars", () => {
  const password = 'My\u200BPass\u200Cword\u200D123\uFEFF!';
  const normalized = normalizePassword(password);
  assertEquals(normalized, 'MyPassword123!');
});

Deno.test("Normalization - Applies NFKC normalization", () => {
  // Using composed vs decomposed Unicode
  const password1 = 'Café123!ABCD'; // é as single char
  const password2 = 'Café123!ABCD'; // é as e + combining accent
  const norm1 = normalizePassword(password1);
  const norm2 = normalizePassword(password2);
  assertEquals(norm1, norm2);
});

Deno.test("Normalization - Collapses multiple spaces to single space", () => {
  const password = 'correct    horse    battery    staple';
  const normalized = normalizePassword(password);
  assertEquals(normalized, 'correct horse battery staple');
  const result = validatePassword(normalized);
  assertEquals(result.ok, true);
});

// ============================================================================
// EDGE CASES
// ============================================================================

Deno.test("Edge case - Empty string returns required error", () => {
  const result = validatePassword('');
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('required'), true);
});

Deno.test("Edge case - Only whitespace returns required error", () => {
  const result = validatePassword(normalizePassword('     '));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('required'), true);
});

Deno.test("Edge case - Only control characters", () => {
  const password = '\u0000\u0001\u0002\u0003';
  const result = validatePassword(normalizePassword(password));
  assertEquals(result.ok, false);
  assertEquals(result.codes?.includes('required'), true);
});

Deno.test("Edge case - Exactly 12 characters with 3 classes accepted", () => {
  const result = validatePassword(normalizePassword('MyPassword1!'));
  assertEquals(result.ok, true);
});

Deno.test("Edge case - Exactly 20 characters passphrase accepted", () => {
  const result = validatePassword(normalizePassword('twenty chars phrase!'));
  assertEquals(result.ok, true);
});

Deno.test("Edge case - Max length boundary (128 chars) accepted", () => {
  const password = 'A' + 'b'.repeat(125) + '1!'; // 128 chars with complexity
  const result = validatePassword(normalizePassword(password));
  assertEquals(result.ok, true);
});

Deno.test("Edge case - Password with emojis and symbols: 🔐Secure🔑Pass123!", () => {
  const result = validatePassword(normalizePassword('🔐Secure🔑Pass123!'));
  assertEquals(result.ok, true);
});

Deno.test("Edge case - All 4 character classes: AbCd1234!@#$", () => {
  const result = validatePassword(normalizePassword('AbCd1234!@#$'));
  assertEquals(result.ok, true);
});
