/**
 * Normalize and hash email identifier for privacy and consistency
 * Trims, lowercases, and hashes with SHA-256
 */
export async function normalizeIdentifier(email: string): Promise<string> {
  const normalized = email.trim().toLowerCase();
  
  // Hash for privacy - don't store raw emails in rate limit store
  const encoder = new TextEncoder();
  const data = encoder.encode(normalized);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  
  // Convert to hex string
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
  return hashHex;
}
