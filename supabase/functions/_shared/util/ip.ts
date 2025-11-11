/**
 * Secure client IP extraction with trust boundary enforcement
 * 
 * SECURITY: Proxy headers (Cloudflare, X-Forwarded-For) are ONLY trusted when
 * the request's provenance is verified via:
 * 1. Source IP matching a configured CIDR allowlist, OR
 * 2. Presence of a shared secret header
 * 
 * Without provenance verification, proxy headers are ignored to prevent
 * trust boundary bypass attacks where external clients forge headers.
 * 
 * Trust Modes:
 * - cloudflare: Trust cf-connecting-ip only when provenance verified
 * - xff: Trust x-forwarded-for only when provenance verified
 * - none (default): Do not trust client-provided headers, return null
 * 
 * Environment Variables:
 * - TRUSTED_PROXY_MODE: "cloudflare" | "xff" | "none" (default: "none")
 * - TRUSTED_HOPS: Number of trusted proxies in XFF chain (default: 0)
 * - ALLOW_PRIVATE_IPS: Allow private/reserved IPs (default: "false")
 * 
 * PROVENANCE VERIFICATION (required for cloudflare/xff modes):
 * - TRUSTED_PROXY_CIDRS: Comma-separated CIDR blocks (e.g., "203.0.113.0/24,2001:db8::/32")
 * - TRUSTED_PROXY_SECRET: Shared secret for verifying proxy requests
 * - TRUSTED_PROXY_SECRET_HEADER: Header name containing secret (default: "x-proxy-verified")
 * 
 * Example configuration for Cloudflare:
 *   TRUSTED_PROXY_MODE=cloudflare
 *   TRUSTED_PROXY_CIDRS=173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,...
 * 
 * Example configuration for load balancer with shared secret:
 *   TRUSTED_PROXY_MODE=xff
 *   TRUSTED_HOPS=1
 *   TRUSTED_PROXY_SECRET=your-secret-here
 */

interface IpConfig {
  mode: 'cloudflare' | 'xff' | 'none';
  trustedHops: number;
  allowPrivateIps: boolean;
  trustedProxyCidrs: string[];
  trustedProxySecret: string | undefined;
  trustedProxySecretHeader: string;
}

/**
 * Load configuration from environment with safe defaults
 */
function getConfig(): IpConfig {
  const mode = (Deno.env.get('TRUSTED_PROXY_MODE') || 'none') as IpConfig['mode'];
  const trustedHops = parseInt(Deno.env.get('TRUSTED_HOPS') || '0', 10);
  const allowPrivateIps = Deno.env.get('ALLOW_PRIVATE_IPS') === 'true';
  
  // Parse CIDR blocks from environment
  const cidrsEnv = Deno.env.get('TRUSTED_PROXY_CIDRS') || '';
  const trustedProxyCidrs = cidrsEnv
    .split(',')
    .map(c => c.trim())
    .filter(c => c.length > 0);
  
  const trustedProxySecret = Deno.env.get('TRUSTED_PROXY_SECRET');
  const trustedProxySecretHeader = Deno.env.get('TRUSTED_PROXY_SECRET_HEADER') || 'x-proxy-verified';

  return {
    mode: ['cloudflare', 'xff', 'none'].includes(mode) ? mode : 'none',
    trustedHops: trustedHops >= 0 ? trustedHops : 0,
    allowPrivateIps,
    trustedProxyCidrs,
    trustedProxySecret,
    trustedProxySecretHeader,
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
 * Parse CIDR notation and check if an IP falls within the range
 * Supports both IPv4 and IPv6 CIDR blocks
 */
function isIpInCidr(ip: string, cidr: string): boolean {
  const [network, prefixLenStr] = cidr.split('/');
  const prefixLen = parseInt(prefixLenStr, 10);
  
  if (!network || isNaN(prefixLen)) {
    return false;
  }
  
  // IPv4 CIDR matching
  if (isValidIPv4(ip) && isValidIPv4(network)) {
    if (prefixLen < 0 || prefixLen > 32) return false;
    
    const ipBits = ip.split('.').reduce((acc, octet) => 
      (acc << 8) | parseInt(octet, 10), 0) >>> 0;
    const networkBits = network.split('.').reduce((acc, octet) => 
      (acc << 8) | parseInt(octet, 10), 0) >>> 0;
    
    const mask = (0xFFFFFFFF << (32 - prefixLen)) >>> 0;
    
    return (ipBits & mask) === (networkBits & mask);
  }
  
  // IPv6 CIDR matching (simplified - expands addresses and compares prefix)
  if (isValidIPv6(ip) && isValidIPv6(network)) {
    if (prefixLen < 0 || prefixLen > 128) return false;
    
    // For simplicity, compare string prefixes for common IPv6 forms
    // A full implementation would normalize and bit-compare
    // This covers most practical cases where CIDRs are properly formatted
    const ipNorm = ip.toLowerCase().replace(/^0+/, '').replace(/:0+/g, ':');
    const netNorm = network.toLowerCase().replace(/^0+/, '').replace(/:0+/g, ':');
    
    // Simple prefix match for common cases
    // Note: This is a simplified check. Production systems should use a full IPv6 library
    if (prefixLen % 16 === 0) {
      const hexGroups = prefixLen / 16;
      const ipGroups = ipNorm.split(':').slice(0, hexGroups);
      const netGroups = netNorm.split(':').slice(0, hexGroups);
      return ipGroups.join(':') === netGroups.join(':');
    }
    
    // For non-aligned prefixes, fall back to conservative match
    return ipNorm.startsWith(netNorm.split(':').slice(0, Math.floor(prefixLen / 16)).join(':'));
  }
  
  return false;
}

/**
 * Check if IP is in any of the configured CIDR blocks
 */
function isIpInCidrs(ip: string, cidrs: string[]): boolean {
  if (!ip || cidrs.length === 0) return false;
  
  for (const cidr of cidrs) {
    if (isIpInCidr(ip, cidr)) {
      return true;
    }
  }
  
  return false;
}

/**
 * SECURITY: Verify that the request actually came from a trusted proxy
 * 
 * This prevents trust boundary bypass attacks where external clients
 * forge Cloudflare or X-Forwarded-For headers to bypass security controls.
 * 
 * Provenance is established through:
 * 1. Source IP matching configured CIDR allowlist (TRUSTED_PROXY_CIDRS), OR
 * 2. Presence of valid shared secret header
 * 
 * @param headers Request headers
 * @param peerIp Direct peer/source IP (if available)
 * @param config IP configuration with trust settings
 * @returns true if provenance is verified, false otherwise
 */
function isTrustedProxySource(
  headers: Headers,
  peerIp: string | null,
  config: IpConfig
): boolean {
  // Check 1: Source IP in CIDR allowlist
  if (peerIp && config.trustedProxyCidrs.length > 0) {
    if (isIpInCidrs(peerIp, config.trustedProxyCidrs)) {
      return true;
    }
  }
  
  // Check 2: Shared secret header verification
  if (config.trustedProxySecret) {
    const providedSecret = headers.get(config.trustedProxySecretHeader);
    if (providedSecret === config.trustedProxySecret) {
      return true;
    }
  }
  
  // No provenance established - do not trust proxy headers
  return false;
}

/**
 * Check if request is from Cloudflare by verifying Cloudflare-specific headers
 * 
 * SECURITY NOTE: This check alone is NOT sufficient for trust.
 * Always combine with isTrustedProxySource() to verify provenance.
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
    .filter(ip => ip.length > 0 && isValidIp(ip));
  
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
 * SECURITY: This function enforces provenance verification before trusting
 * proxy headers. Without verified provenance, proxy headers are IGNORED.
 * 
 * @param req Request object
 * @param peerIp Optional: Direct peer/source IP address for provenance verification
 * @returns Client IP address or null if trust cannot be established
 * 
 * @example
 * // Cloudflare mode with CIDR verification
 * // env: TRUSTED_PROXY_MODE=cloudflare
 * // env: TRUSTED_PROXY_CIDRS=173.245.48.0/20,...
 * const ip = getClientIp(req, peerIp); // Returns cf-connecting-ip only if peerIp in CIDR
 * 
 * @example
 * // XFF mode with shared secret
 * // env: TRUSTED_PROXY_MODE=xff
 * // env: TRUSTED_HOPS=1
 * // env: TRUSTED_PROXY_SECRET=my-secret
 * const ip = getClientIp(req); // Returns XFF IP only if x-proxy-verified header matches
 * 
 * @example
 * // None mode (default - safe fallback)
 * const ip = getClientIp(req); // Returns null (ignores all proxy headers)
 */
export function getClientIp(req: Request, peerIp?: string | null): string | null {
  const config = getConfig();
  const headers = req.headers;
  
  // Determine actual peer IP (use parameter if provided, otherwise try to extract)
  const actualPeerIp = peerIp ?? null;
  
  // Mode: Cloudflare - Trust cf-connecting-ip ONLY if provenance verified
  if (config.mode === 'cloudflare') {
    // SECURITY: Verify request actually came from a trusted proxy
    if (!isTrustedProxySource(headers, actualPeerIp, config)) {
      // Provenance not verified - ignore Cloudflare headers to prevent spoofing
      return actualPeerIp && isValidIp(actualPeerIp) ? actualPeerIp : null;
    }
    
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
    return actualPeerIp && isValidIp(actualPeerIp) ? actualPeerIp : null;
  }
  
  // Mode: XFF - Trust x-forwarded-for ONLY if provenance verified
  if (config.mode === 'xff') {
    // SECURITY: Verify request actually came from a trusted proxy
    if (!isTrustedProxySource(headers, actualPeerIp, config)) {
      // Provenance not verified - ignore XFF headers to prevent spoofing
      return actualPeerIp && isValidIp(actualPeerIp) ? actualPeerIp : null;
    }
    
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
    return actualPeerIp && isValidIp(actualPeerIp) ? actualPeerIp : null;
  }
  
  // Mode: None (default) - Do not trust any client-provided headers
  // Return peer IP if available and valid, otherwise null
  return actualPeerIp && isValidIp(actualPeerIp) ? actualPeerIp : null;
}
