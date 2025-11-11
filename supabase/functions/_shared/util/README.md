# IP Extraction Security Configuration

This directory contains the secure client IP extraction utility with trust boundary enforcement.

## Configuration

The `getClientIp` function supports three trust modes controlled by environment variables:

### Environment Variables

- **TRUSTED_PROXY_MODE**: `"cloudflare"` | `"xff"` | `"none"` (default: `"none"`)
- **TRUSTED_HOPS**: Number of trusted proxy hops in XFF chain (default: `0`)
- **ALLOW_PRIVATE_IPS**: Allow private/reserved IPs (default: `"false"`)

### Trust Modes

#### 1. None Mode (Default - Secure)
```bash
TRUSTED_PROXY_MODE=none
```
- **Behavior**: Returns `null` for all requests
- **Use Case**: Maximum security when you cannot trust any proxy headers
- **Security**: Prevents all IP spoofing attacks
- **Note**: Rate limiting will rely solely on identifier-based limits

#### 2. Cloudflare Mode
```bash
TRUSTED_PROXY_MODE=cloudflare
```
- **Behavior**: Trusts `cf-connecting-ip` only when Cloudflare headers (`cf-ray` or `cf-visitor`) are present
- **Use Case**: When your app is behind Cloudflare CDN
- **Security**: Validates Cloudflare provenance before trusting the IP
- **Rejects**: Spoofed `x-forwarded-for` and `x-real-ip` headers

#### 3. X-Forwarded-For Mode
```bash
TRUSTED_PROXY_MODE=xff
TRUSTED_HOPS=1
```
- **Behavior**: Extracts client IP from `x-forwarded-for` after removing trusted proxy hops
- **Use Case**: When behind a reverse proxy or load balancer
- **Security**: Requires explicit configuration of trusted hop count
- **Example**: 
  - XFF header: `"client-ip, proxy1-ip, proxy2-ip"`
  - With `TRUSTED_HOPS=1`: Returns `"proxy1-ip"` (second from right)
  - With `TRUSTED_HOPS=2`: Returns `"client-ip"` (third from right)

## IP Validation

All extracted IPs are validated for:

1. **Format Validation**: Must be valid IPv4 or IPv6
2. **Private/Reserved IP Filtering**: (when `ALLOW_PRIVATE_IPS=false`)
   - RFC1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - Loopback: `127.0.0.0/8`, `::1`
   - Link-local: `169.254.0.0/16`, `fe80::/10`
   - Multicast, reserved, and unspecified addresses

## Security Best Practices

### Production Deployment

1. **Use Cloudflare Mode** if behind Cloudflare:
   ```bash
   TRUSTED_PROXY_MODE=cloudflare
   ALLOW_PRIVATE_IPS=false
   ```

2. **Use XFF Mode** if behind a trusted reverse proxy:
   ```bash
   TRUSTED_PROXY_MODE=xff
   TRUSTED_HOPS=1  # Adjust based on your proxy chain
   ALLOW_PRIVATE_IPS=false
   ```

3. **Default Mode** for maximum security:
   ```bash
   TRUSTED_PROXY_MODE=none
   ```

### Testing/Development

For local development, you may need to allow private IPs:
```bash
TRUSTED_PROXY_MODE=xff
TRUSTED_HOPS=0
ALLOW_PRIVATE_IPS=true
```

## Attack Prevention

This implementation prevents:

- ✅ **X-Forwarded-For Spoofing**: Client-controlled headers are ignored unless explicitly trusted
- ✅ **IP Allowlist Bypass**: Untrusted IPs cannot be used for allowlist checks
- ✅ **Rate Limit Evasion**: Attackers cannot forge IPs to bypass per-IP rate limits
- ✅ **Log Poisoning**: Forged IPs are rejected, maintaining log integrity

## Testing

Run the test suite to verify security:

```bash
deno test -A supabase/functions/_shared/util/ip_test.ts
```

## Example Usage

```typescript
import { getClientIp } from '../_shared/util/ip.ts';

const ip = getClientIp(req);
// Returns: string (trusted IP) | null (untrusted)

if (ip !== null) {
  // Use IP for rate limiting, logging, etc.
  await rateLimiter.checkAndConsume(ip, identifier);
} else {
  // Fall back to identifier-only rate limiting
  await rateLimiter.checkAndConsume(null, identifier);
}
```

## Migration Notes

If upgrading from the previous insecure version:

1. The function now returns `string | null` instead of `string`
2. Default behavior is secure (`mode: none` returns `null`)
3. Update all callers to handle `null` IPs gracefully
4. Configure the appropriate trust mode for your deployment
