# IP Extraction Security: Trust Boundary Enforcement

## Critical Security Update

The IP extraction utility (`supabase/functions/_shared/util/ip.ts`) has been hardened against **trust boundary bypass attacks**. Proxy headers (Cloudflare, X-Forwarded-For) are now **ONLY** trusted when provenance is properly verified.

---

## Vulnerability Fixed

### Before (Vulnerable)
```typescript
// ❌ INSECURE: Trusted headers based on presence alone
if (config.mode === 'cloudflare') {
  const cfIp = headers.get('cf-connecting-ip');
  if (cfIp && headers.has('cf-ray')) {
    return cfIp; // No verification that request actually from Cloudflare!
  }
}
```

**Attack**: External attacker sends `cf-connecting-ip: 8.8.8.8` with `cf-ray: fake` to bypass IP allowlists.

### After (Secure)
```typescript
// ✅ SECURE: Requires provenance verification
if (config.mode === 'cloudflare') {
  if (!isTrustedProxySource(headers, peerIp, config)) {
    return peerIp; // Ignore spoofable headers without proof
  }
  // Only now can we trust cf-connecting-ip
}
```

**Protection**: Headers ignored unless request provably came from trusted proxy.

---

## How Provenance Verification Works

Provenance is established through **either** of these methods:

### 1. CIDR Allowlist (Recommended)
Verify the request's **source IP** matches configured CIDR blocks:

```bash
# Example: Cloudflare IP ranges
export TRUSTED_PROXY_CIDRS="173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20"
export TRUSTED_PROXY_MODE="cloudflare"
```

**How it works**: Function checks if the actual peer IP (the server that connected to your edge function) falls within the allowed ranges. Only then are `cf-*` headers trusted.

### 2. Shared Secret Header
Verify a shared secret header set by your trusted proxy:

```bash
export TRUSTED_PROXY_SECRET="your-secret-token-here"
export TRUSTED_PROXY_SECRET_HEADER="x-proxy-verified"  # Optional, defaults to x-proxy-verified
export TRUSTED_PROXY_MODE="xff"
export TRUSTED_HOPS="1"
```

Configure your load balancer to add:
```
X-Proxy-Verified: your-secret-token-here
```

---

## Configuration Reference

### Environment Variables

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `TRUSTED_PROXY_MODE` | `cloudflare` \| `xff` \| `none` | `none` | Trust mode for proxy headers |
| `TRUSTED_PROXY_CIDRS` | Comma-separated CIDR blocks | `""` | Allowed source IPs (e.g., `203.0.113.0/24,192.0.2.0/24`) |
| `TRUSTED_PROXY_SECRET` | Any string | `undefined` | Shared secret for proxy authentication |
| `TRUSTED_PROXY_SECRET_HEADER` | Header name | `x-proxy-verified` | Header containing the secret |
| `TRUSTED_HOPS` | Number ≥ 0 | `0` | Trusted proxies in XFF chain |
| `ALLOW_PRIVATE_IPS` | `true` \| `false` | `false` | Allow private/reserved IPs |

### Trust Modes

#### `none` (Default - Safest)
```bash
export TRUSTED_PROXY_MODE="none"
```
- Ignores ALL proxy headers
- Returns peer IP if available, otherwise `null`
- Use when not behind a proxy

#### `cloudflare`
```bash
export TRUSTED_PROXY_MODE="cloudflare"
export TRUSTED_PROXY_CIDRS="173.245.48.0/20,..."  # Cloudflare ranges
```
- Trusts `cf-connecting-ip` **only** when provenance verified
- Requires `cf-ray` or `cf-visitor` header presence
- Falls back to peer IP if provenance fails

#### `xff` (X-Forwarded-For)
```bash
export TRUSTED_PROXY_MODE="xff"
export TRUSTED_HOPS="1"
export TRUSTED_PROXY_SECRET="load-balancer-secret"
```
- Trusts `x-forwarded-for` **only** when provenance verified
- Extracts client IP using `trustedHops` to skip known proxies
- Falls back to peer IP if provenance fails

---

## Security Guarantees

### ✅ What's Protected

1. **IP Allowlist Bypass**: Attackers cannot forge headers to claim allowlisted IPs
2. **Rate Limit Evasion**: Attackers cannot rotate IPs via headers to evade per-IP limits
3. **Geo Restriction Bypass**: Attackers cannot spoof location via forged IPs
4. **Audit Log Poisoning**: Logs reflect actual source IPs, not attacker-controlled values

### ⚠️ Requirements

- **CIDR Mode**: Must have access to peer IP (source IP of the connection)
- **Secret Mode**: Proxy must be configured to add the secret header
- **Both**: At least one provenance method must be configured for non-`none` modes

---

## Example Configurations

### Cloudflare with CIDR Verification
```bash
# Use Cloudflare IP ranges (get latest from https://www.cloudflare.com/ips/)
export TRUSTED_PROXY_MODE="cloudflare"
export TRUSTED_PROXY_CIDRS="173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22"
```

### Load Balancer with Shared Secret
```bash
export TRUSTED_PROXY_MODE="xff"
export TRUSTED_HOPS="1"
export TRUSTED_PROXY_SECRET="$(openssl rand -hex 32)"
export TRUSTED_PROXY_SECRET_HEADER="x-lb-auth"
```

Configure your load balancer (e.g., nginx):
```nginx
location / {
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-LB-Auth "YOUR_SECRET_HERE";
  proxy_pass http://backend;
}
```

### Development (No Proxy)
```bash
export TRUSTED_PROXY_MODE="none"
```

---

## Testing Your Configuration

### Manual Security Test

1. **Test Header Spoofing (Should Fail)**:
```bash
curl -H "cf-connecting-ip: 8.8.8.8" \
     -H "cf-ray: fake-ray" \
     https://your-function-url
```
Expected: Your actual IP logged, not `8.8.8.8`

2. **Test With Valid Provenance (Should Succeed)**:
```bash
# Only works if your request actually comes through Cloudflare
curl https://your-function-url
```
Expected: Correct client IP from `cf-connecting-ip`

### Automated Tests

Run the comprehensive test suite:
```bash
deno test supabase/functions/_shared/util/ip_provenance_test.ts
```

Tests cover:
- ✅ Provenance verification (CIDR & secret)
- ✅ Header spoofing prevention
- ✅ Correct IP extraction when verified
- ✅ IPv4 and IPv6 CIDR matching
- ✅ Edge cases and error handling

---

## Migration Guide

### If You Were Using Cloudflare Mode

**Before** (insecure):
```typescript
export const ip = getClientIp(req);
// Trusted cf-connecting-ip without verification
```

**After** (secure):
```bash
# Add to your environment:
export TRUSTED_PROXY_CIDRS="173.245.48.0/20,..."  # Cloudflare ranges
```

```typescript
export const ip = getClientIp(req);
// Now verifies request actually from Cloudflare before trusting headers
```

### If You Were Using XFF Mode

**Before** (insecure):
```bash
export TRUSTED_PROXY_MODE="xff"
export TRUSTED_HOPS="1"
```

**After** (secure):
```bash
export TRUSTED_PROXY_MODE="xff"
export TRUSTED_HOPS="1"
# Add provenance verification:
export TRUSTED_PROXY_SECRET="your-secret-here"
# OR
export TRUSTED_PROXY_CIDRS="192.0.2.0/24"  # Your LB IP range
```

---

## Troubleshooting

### Issue: Always Getting `null` or Peer IP

**Cause**: Provenance not configured or failing
**Fix**: 
1. Check `TRUSTED_PROXY_CIDRS` includes your proxy's source IP
2. OR ensure `TRUSTED_PROXY_SECRET` matches what your proxy sends
3. Verify `TRUSTED_PROXY_MODE` is set correctly

### Issue: Getting Wrong IP

**Cause**: Incorrect `TRUSTED_HOPS` configuration
**Fix**: Count your proxy chain:
- 1 proxy → `TRUSTED_HOPS=0`
- 2 proxies → `TRUSTED_HOPS=1`
- etc.

### Issue: Private IPs Rejected

**Cause**: `ALLOW_PRIVATE_IPS` not set
**Fix**: For development/internal networks:
```bash
export ALLOW_PRIVATE_IPS="true"
```

---

## Performance Impact

- **CIDR Matching**: O(n) where n = number of configured CIDRs (typically <50)
- **Secret Verification**: O(1) string comparison
- **Overall**: Negligible overhead (<1ms per request)

---

## Security Best Practices

1. **Use CIDR Verification** when possible (more secure than shared secrets)
2. **Keep CIDR Lists Updated**: Subscribe to proxy provider's IP change notifications
3. **Rotate Secrets Regularly**: If using shared secret mode
4. **Default to `none`**: Only enable proxy trust when necessary
5. **Monitor Logs**: Watch for unexpected fallback to peer IPs

---

## References

- Cloudflare IP Ranges: https://www.cloudflare.com/ips/
- RFC 7239 (Forwarded HTTP Extension): https://tools.ietf.org/html/rfc7239
- OWASP: Unvalidated Redirects and Forwards

---

## Support

For questions or issues:
1. Review test suite: `supabase/functions/_shared/util/ip_provenance_test.ts`
2. Check configuration: Ensure environment variables are set correctly
3. Verify provenance: Log `peerIp` to confirm source IP expectations
