/**
 * Secure client IP extraction with trust boundary enforcement
 * 
 * Trust Modes:
 * - cloudflare: Trust cf-connecting-ip only when Cloudflare headers are present
 * - xff: Trust x-forwarded-for with configured trusted proxy hops
 * - none (default): Do not trust client-provided headers, return null
 * 
 * Environment Variables:
 * - TRUSTED_PROXY_MODE: "cloudflare" | "xff" | "none" (default: "none")
 * - TRUSTED_HOPS: Number of trusted proxies in XFF chain (default: 0)
 * - ALLOW_PRIVATE_IPS: Allow private/reserved IPs (default: "false")
 */

interface IpConfig {
  mode: 'cloudflare' | 'xff' | 'none';
  trustedHops: number;
  allowPrivateIps: boolean;
}

/**
 * Load configuration from environment with safe defaults
 */
function getConfig(): IpConfig {
  const mode = (Deno.env.get('TRUSTED_PROXY_MODE') || 'none') as IpConfig['mode'];
  const trustedHops = parseInt(Deno.env.get('TRUSTED_HOPS') || '0', 10);
  const allowPrivateIps = Deno.env.get('ALLOW_PRIVATE_IPS') === 'true';

  return {
    mode: ['cloudflare', 'xff', 'none'].includes(mode) ? mode : 'none',
    trustedHops: trustedHops >= 0 ? trustedHops : 0,
    allowPrivateIps,
  };
}

/**
 * Validate IPv4 address format
 */
function isValidIPv4(ip: string): boolean {
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = ip.match(ipv4Regex);
  if (!match) return false;
  
  // Check each octet is 0-255
  for (let i = 1; i <= 4; i++) {
    const octet = parseInt(match[i], 10);
    if (octet < 0 || octet > 255) return false;
  }
  return true;
}

/**
 * Validate IPv6 address format (simplified check for common formats)
 */
function isValidIPv6(ip: string): boolean {
  // Simplified IPv6 validation - accepts standard forms
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|::)$/;
  return ipv6Regex.test(ip);
}

/**
 * Validate IP address format (IPv4 or IPv6)
 */
function isValidIp(ip: string): boolean {
  const trimmed = ip.trim();
  return isValidIPv4(trimmed) || isValidIPv6(trimmed);
}

/**
 * Check if IP is private or reserved
 * RFC1918, loopback, link-local, multicast, etc.
 */
function isPrivateOrReserved(ip: string): boolean {
  const trimmed = ip.trim();
  
  // IPv4 private/reserved ranges
  if (isValidIPv4(trimmed)) {
    const parts = trimmed.split('.').map(p => parseInt(p, 10));
    
    // RFC1918 private ranges
    if (parts[0] === 10) return true; // 10.0.0.0/8
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12
    if (parts[0] === 192 && parts[1] === 168) return true; // 192.168.0.0/16
    
    // Loopback
    if (parts[0] === 127) return true; // 127.0.0.0/8
    
    // Link-local
    if (parts[0] === 169 && parts[1] === 254) return true; // 169.254.0.0/16
    
    // Multicast
    if (parts[0] >= 224 && parts[0] <= 239) return true; // 224.0.0.0/4
    
    // Reserved
    if (parts[0] >= 240) return true; // 240.0.0.0/4
    
    // Unspecified
    if (parts[0] === 0) return true; // 0.0.0.0/8
    
    return false;
  }
  
  // IPv6 private/reserved ranges
  if (isValidIPv6(trimmed)) {
    const lower = trimmed.toLowerCase();
    
    // Loopback
    if (lower === '::1') return true;
    
    // Unspecified
    if (lower === '::') return true;
    
    // Link-local
    if (lower.startsWith('fe80:')) return true;
    
    // Unique local
    if (lower.startsWith('fc00:') || lower.startsWith('fd00:')) return true;
    
    // Multicast
    if (lower.startsWith('ff00:')) return true;
    
    return false;
  }
  
  return true; // If we can't validate format, treat as reserved
}

/**
 * Check if request is from Cloudflare by verifying Cloudflare-specific headers
 */
function isCloudflare(headers: Headers): boolean {
  // Cloudflare adds cf-ray and other headers that are harder to spoof
  return headers.has('cf-ray') || headers.has('cf-visitor');
}

/**
 * Extract client IP from X-Forwarded-For with trusted hops
 * @param xff X-Forwarded-For header value
 * @param trustedHops Number of trusted proxy hops to remove from the right
 * @returns Client IP or null if invalid
 */
function extractFromXff(xff: string, trustedHops: number): string | null {
  const ips = xff
    .split(',')
    .map(ip => ip.trim())
    .filter(ip => isValidIp(ip));
  
  if (ips.length === 0) return null;
  
  // Calculate client IP index: total IPs - 1 (for 0-index) - trusted hops
  const clientIndex = ips.length - 1 - trustedHops;
  
  if (clientIndex < 0 || clientIndex >= ips.length) {
    return null; // Invalid configuration or insufficient IPs
  }
  
  return ips[clientIndex];
}

/**
 * Extract client IP address from request headers with strict trust boundary
 * 
 * @param req Request object
 * @returns Client IP address or null if trust cannot be established
 * 
 * @example
 * // Cloudflare mode (env: TRUSTED_PROXY_MODE=cloudflare)
 * const ip = getClientIp(req); // Returns cf-connecting-ip if Cloudflare verified
 * 
 * @example
 * // XFF mode (env: TRUSTED_PROXY_MODE=xff, TRUSTED_HOPS=1)
 * const ip = getClientIp(req); // Returns correct client IP from XFF chain
 * 
 * @example
 * // None mode (default)
 * const ip = getClientIp(req); // Returns null (safe default)
 */
export function getClientIp(req: Request): string | null {
  const config = getConfig();
  const headers = req.headers;
  
  // Mode: Cloudflare - Trust cf-connecting-ip only if verified Cloudflare
  if (config.mode === 'cloudflare') {
    const cfIp = headers.get('cf-connecting-ip');
    if (cfIp && isCloudflare(headers)) {
      const trimmed = cfIp.trim();
      if (isValidIp(trimmed)) {
        if (!config.allowPrivateIps && isPrivateOrReserved(trimmed)) {
          return null;
        }
        return trimmed;
      }
    }
    return null;
  }
  
  // Mode: XFF - Trust x-forwarded-for with configured trusted hops
  if (config.mode === 'xff') {
    const xff = headers.get('x-forwarded-for');
    if (xff) {
      const clientIp = extractFromXff(xff, config.trustedHops);
      if (clientIp && isValidIp(clientIp)) {
        if (!config.allowPrivateIps && isPrivateOrReserved(clientIp)) {
          return null;
        }
        return clientIp;
      }
    }
    return null;
  }
  
  // Mode: None (default) - Do not trust any client-provided headers
  return null;
}
