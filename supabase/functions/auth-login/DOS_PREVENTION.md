# DoS Prevention - Request Size Limiting

## Vulnerability Fixed

**Issue**: The auth-login function previously parsed the entire JSON request body without size validation, allowing attackers to send multi-megabyte payloads that would be fully parsed into memory, consuming CPU and memory resources.

**Impact**: Service degradation, timeout failures, and potential unavailability for legitimate users during a DoS attack.

## Implementation

### 1. Request Size Limiting (32KB max)

The function now enforces a strict 32KB limit on request bodies using two strategies:

#### Fast Path: Content-Length Header
- Check `Content-Length` header before reading body
- Immediately reject with 413 if > 32KB
- No memory allocation for oversized requests

#### Slow Path: Streaming Read
- For chunked transfer encoding or missing Content-Length
- Stream body incrementally with running byte counter
- Abort read and return 413 once limit exceeded
- Prevents memory exhaustion from unbounded streams

```typescript
const MAX_BODY_BYTES = 32 * 1024; // 32KB

async function readLimitedBody(req: Request, maxBytes: number): Promise<string> {
  const contentLength = req.headers.get('content-length');
  
  if (contentLength) {
    const length = parseInt(contentLength, 10);
    if (length > maxBytes) {
      throw new Error('PAYLOAD_TOO_LARGE');
    }
    return await req.text();
  }
  
  // Stream with limit for chunked encoding...
}
```

### 2. Pre-Parse Validation

Before expensive JSON parsing:

1. **Method Validation**: Only POST allowed (405 for others)
2. **Content-Type Validation**: Must be `application/json` (415 for others)
3. **Body Size Check**: Enforce 32KB limit
4. **Safe JSON Parsing**: Use try/catch to handle malformed JSON

### 3. Schema Validation

After parsing, strict validation prevents injection and abuse:

```typescript
// Email constraints
- Min length: 3 characters
- Max length: 254 characters (RFC 5321)
- Format: Basic RFC 5322 regex validation
- Normalization: Trim whitespace, lowercase

// Password constraints
- Min length: 8 characters
- Max length: 256 characters
- No normalization (preserve original for bcrypt)
```

### 4. Error Responses

Clear, secure error messages:
- **413 Payload Too Large**: Body exceeds 32KB
- **415 Unsupported Media Type**: Wrong Content-Type
- **405 Method Not Allowed**: Non-POST request
- **400 Bad Request**: Invalid JSON, schema, or field constraints

All responses include CORS headers and proper `Content-Type: application/json`.

## Testing

Run security tests:
```bash
deno test --allow-net --allow-env supabase/functions/auth-login/body_size_test.ts
```

### Test Coverage

1. **Security Tests**:
   - ✅ Reject 100KB payload (oversized with Content-Length)
   - ✅ Reject non-POST methods (GET, PUT, DELETE)
   - ✅ Reject wrong Content-Type (text/plain, etc.)
   - ✅ Reject invalid JSON syntax
   - ✅ Reject email > 254 chars
   - ✅ Reject password < 8 chars
   - ✅ Reject invalid email format

2. **Functionality Tests**:
   - ✅ Accept valid login payload
   - ✅ Normalize email (trim + lowercase)
   - ✅ Preserve password case

### Manual Testing with curl

```bash
# Test oversized payload
curl -i -X POST https://<project>.supabase.co/functions/v1/auth-login \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ANON_KEY" \
  --data '{"email":"test@example.com","password":"'$(python -c 'print("A"*100000)')'"}'
# Expected: 413 Payload Too Large

# Test invalid method
curl -i -X GET https://<project>.supabase.co/functions/v1/auth-login \
  -H "Authorization: Bearer $ANON_KEY"
# Expected: 405 Method Not Allowed, Allow: POST

# Test wrong Content-Type
curl -i -X POST https://<project>.supabase.co/functions/v1/auth-login \
  -H 'Content-Type: text/plain' \
  -H "Authorization: Bearer $ANON_KEY" \
  --data 'not json'
# Expected: 415 Unsupported Media Type

# Test valid request
curl -i -X POST https://<project>.supabase.co/functions/v1/auth-login \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ANON_KEY" \
  --data '{"email":"test@example.com","password":"ValidPass123"}'
# Expected: 401 (invalid creds) or 200 (valid creds)
```

## Performance Impact

**Before**: 
- Unbounded parsing of entire body into memory
- No early rejection of malicious requests
- Vulnerable to memory exhaustion

**After**:
- Content-Length check: O(1) rejection for oversized requests
- Streaming read: Bounded memory (max 32KB + overhead)
- Early validation prevents expensive operations
- Minimal overhead for legitimate requests (<1ms)

## Security Considerations

1. **32KB Limit Rationale**:
   - Typical login payload: ~100-200 bytes
   - 32KB provides 100x+ safety margin
   - Small enough to prevent DoS, large enough for legitimate use

2. **Defense in Depth**:
   - Size limiting (this fix)
   - Rate limiting (already implemented)
   - Schema validation (this fix)
   - Input sanitization (email normalization)

3. **Fail-Safe Behavior**:
   - Invalid requests rejected early
   - No partial parsing or state corruption
   - Clear error messages (no info leakage)

## Related Security Features

- **Rate Limiting**: `/supabase/functions/_shared/security/rateLimiter.ts`
- **CSRF Protection**: `/supabase/functions/auth-logout/index.ts`
- **Input Validation**: This file (auth-login)
- **Session Security**: HttpOnly cookies, in-memory storage

## References

- OWASP: [Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)
- RFC 5321: [SMTP - Email Size Limits](https://datatracker.ietf.org/doc/html/rfc5321#section-4.5.3.1.3)
- CWE-770: [Allocation of Resources Without Limits](https://cwe.mitre.org/data/definitions/770.html)
