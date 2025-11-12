# CORS Security Fix - Auth Session Endpoint

## Vulnerability Fixed

**Issue**: The auth-session endpoint previously used `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`, which is:
1. **Non-compliant with CORS spec** - Wildcard origins cannot be used with credentials
2. **Security risk** - Any website could make credentialed cross-origin requests
3. **Data leakage** - In relaxed CORS environments (WebViews, Electron), authenticated session data could be exposed to malicious origins

**Impact**: Potential exposure of sensitive session data including:
- User ID
- User email  
- Admin status
- Authentication state

## Implementation

### 1. Strict Origin Allowlist

The CORS utility now enforces a strict allowlist of trusted origins:

```typescript
// Default to local development origins (never wildcard)
const defaultOrigins = [
  'http://localhost:8080',
  'http://localhost:5173',
  'http://127.0.0.1:8080',
  'http://127.0.0.1:5173',
];

// Production: Load from ALLOWED_ORIGINS environment variable
ALLOWED_ORIGINS=https://app.example.com,https://www.example.com
```

### 2. Dynamic Origin Validation

**Before**: Static wildcard header applied to all responses
```typescript
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',  // ❌ UNSAFE
  'Access-Control-Allow-Credentials': 'true',  // ❌ VIOLATES CORS SPEC
};
```

**After**: Dynamic validation with exact origin echo
```typescript
const origin = req.headers.get('origin');
if (origin && allowedOrigins.has(origin)) {
  headers.set('Access-Control-Allow-Origin', origin);  // ✅ Exact echo
  headers.set('Vary', 'Origin');  // ✅ Proper caching
  if (allowCredentials) {
    headers.set('Access-Control-Allow-Credentials', 'true');  // ✅ Only for allowed origins
  }
}
```

### 3. Preflight Handling

**Disallowed origins** → 403 Forbidden (no CORS headers)
```bash
curl -i -X OPTIONS https://<project>.supabase.co/functions/v1/auth-session \
  -H 'Origin: https://evil.example.com' \
  -H 'Access-Control-Request-Method: GET'
# Response: 403 Forbidden
# Headers: No Access-Control-Allow-Origin
```

**Allowed origins** → 204 No Content with strict headers
```bash
curl -i -X OPTIONS https://<project>.supabase.co/functions/v1/auth-session \
  -H 'Origin: https://app.example.com' \
  -H 'Access-Control-Request-Method: GET'
# Response: 204 No Content
# Headers:
#   Access-Control-Allow-Origin: https://app.example.com
#   Access-Control-Allow-Credentials: true
#   Vary: Origin
```

### 4. Credentialed Request Protection

**Rejects** cross-origin requests with credentials from disallowed origins:

```typescript
// SECURITY: Prevent session leakage in relaxed CORS environments
if (!origin && req.headers.get('origin')) {
  if (hasCredentials(req)) {
    return new Response(
      JSON.stringify({ error: 'Forbidden: Cross-origin request not allowed' }),
      { status: 403 }
    );
  }
}
```

This protects against:
- Embedded WebViews with relaxed CORS enforcement
- Electron apps with custom CORS policies
- Legacy browsers with incomplete CORS implementation

### 5. Vary Header for Proper Caching

Always includes `Vary: Origin` when echoing origin:

```typescript
headers.set('Vary', 'Origin');
```

This ensures CDNs and proxies cache responses per-origin, preventing cache poisoning attacks.

## Configuration

### Environment Variables

Create `supabase/functions/.env` (not committed):

```bash
# Production origins
ALLOWED_ORIGINS=https://app.example.com,https://www.example.com

# Enable credentials for authenticated endpoints (default: true)
ALLOW_CREDENTIALS=true
```

### Default Behavior

If `ALLOWED_ORIGINS` is not set:
- ✅ Defaults to local development origins
- ✅ **NEVER** defaults to wildcard (*)
- ✅ Safe by default

## Testing

Run CORS security tests:
```bash
deno test --allow-net --allow-env supabase/functions/auth-session/cors_test.ts
```

### Test Coverage

1. **Security Tests**:
   - ✅ Reject preflight from disallowed origin (403, no ACAO)
   - ✅ Reject credentialed GET from disallowed origin (403)
   - ✅ No wildcard origin in any response
   - ✅ No credentials+wildcard combination

2. **Functionality Tests**:
   - ✅ Accept preflight from allowed origin (localhost)
   - ✅ Allowed origin receives proper headers on GET
   - ✅ Same-origin request works without CORS headers
   - ✅ Vary: Origin header present

### Manual Testing

```bash
# Set environment variable for testing
export SUPABASE_URL="https://your-project.supabase.co"
export SUPABASE_ANON_KEY="your-anon-key"

# Test disallowed origin (should be 403)
curl -i -X OPTIONS $SUPABASE_URL/functions/v1/auth-session \
  -H 'Origin: https://evil.example.com' \
  -H 'Access-Control-Request-Method: GET'

# Test allowed origin (should be 204 with headers)
curl -i -X OPTIONS $SUPABASE_URL/functions/v1/auth-session \
  -H 'Origin: http://localhost:8080' \
  -H 'Access-Control-Request-Method: GET'

# Test credentialed request from disallowed origin (should be 403)
curl -i $SUPABASE_URL/functions/v1/auth-session \
  -H 'Origin: https://evil.example.com' \
  -H "Authorization: Bearer $SUPABASE_ANON_KEY" \
  -H 'Cookie: sb-session=fake'

# Test same-origin request (should work, no CORS headers needed)
curl -i $SUPABASE_URL/functions/v1/auth-session \
  -H "Authorization: Bearer $SUPABASE_ANON_KEY"
```

## Security Improvements

### Before (Vulnerable)
- ❌ Wildcard origin with credentials
- ❌ No origin validation
- ❌ No Vary header
- ❌ Permissive for all origins
- ❌ CORS spec violation

### After (Secure)
- ✅ Strict origin allowlist
- ✅ Dynamic origin validation
- ✅ Vary: Origin for proper caching
- ✅ Rejects disallowed origins (403)
- ✅ CORS spec compliant
- ✅ Credentials only for trusted origins
- ✅ Protection for relaxed CORS environments

## Performance Impact

**Minimal overhead**:
- O(1) Set lookup for origin validation
- No additional network requests
- Negligible CPU impact

## Related Security Features

- **CSRF Protection**: `/supabase/functions/auth-logout/index.ts`
- **Request Size Limiting**: `/supabase/functions/auth-login/index.ts`
- **Input Validation**: Multiple edge functions
- **Rate Limiting**: `/supabase/functions/_shared/security/rateLimiter.ts`

## References

- [CORS Specification](https://fetch.spec.whatwg.org/#http-cors-protocol)
- [OWASP CORS Guide](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny)
- [MDN CORS Documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [CWE-942: Permissive Cross-domain Policy](https://cwe.mitre.org/data/definitions/942.html)
