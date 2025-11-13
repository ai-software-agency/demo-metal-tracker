# Admin MFA/Step-Up Authentication Enforcement

## Overview

The `check-admin` edge function enforces **step-up authentication** for administrative privilege verification. This ensures that only users with recent multi-factor authentication can access admin-level features, following OWASP A07:2021 and PCI DSS 8.3 requirements.

## Vulnerability Fixed

### Issue
The original implementation granted admin status based solely on JWT possession and role membership. Any attacker with a stolen admin JWT could access admin features without additional verification.

### Impact
- **Attack Vector**: Stolen JWT (via XSS, phishing, malware, or logs)
- **Risk**: Unauthorized admin access leading to data compromise and system changes
- **Compliance**: Violated OWASP A07:2021, PCI DSS 8.3

## Security Enhancements

### 1. Multi-Factor Authentication (AAL2) Requirement

**What is AAL2?**
Authenticator Assurance Level 2 indicates the user has authenticated using multiple factors (something you know + something you have/are).

**Detection Methods:**
- Explicit `aal` claim: `payload.aal === 'aal2'`
- Authentication Methods Reference (`amr`): Contains MFA indicators
  - `mfa` - Generic multi-factor
  - `totp` - Time-based one-time password
  - `webauthn` - Hardware security keys
  - `otp` - One-time password
  - `sms` - SMS-based verification

**Implementation:**
```typescript
function isAAL2(payload: any): boolean {
  if (payload.aal === 'aal2') return true;
  
  if (Array.isArray(payload.amr)) {
    const mfaMethods = ['mfa', 'totp', 'webauthn', 'otp', 'sms'];
    return payload.amr.some(method => mfaMethods.includes(method.toLowerCase()));
  }
  
  return false;
}
```

### 2. Recent Authentication Requirement

**Purpose:**
Ensures the admin session is fresh and the user has recently proven their identity, preventing use of long-lived stolen tokens.

**Validation:**
- Checks `auth_time` (preferred) or `iat` (issued at) claim
- Requires authentication within `ADMIN_STEP_UP_MAX_AGE_SECONDS` (default: 600s / 10 minutes)
- Rejects future timestamps to prevent clock manipulation

**Implementation:**
```typescript
function isRecentAuth(payload: any, maxAgeSeconds: number): boolean {
  const now = Math.floor(Date.now() / 1000);
  const authTime = payload.auth_time || payload.iat;
  
  if (!authTime || typeof authTime !== 'number') return false;
  
  const age = now - authTime;
  return age >= 0 && age <= maxAgeSeconds;
}
```

### 3. Strict CORS Controls

**Changes:**
- Replaced wildcard `Access-Control-Allow-Origin: *` with allowlist-based validation
- Integrated with `_shared/util/cors.ts` for consistent security
- Only echoes allowed origins from `ALLOWED_ORIGINS` environment variable
- Includes `Vary: Origin` header for proper caching
- Rejects preflight from disallowed origins with 403

## Configuration

### Environment Variables

#### `ADMIN_MFA_REQUIRED` (default: `true`)
Require multi-factor authentication for admin checks.
```bash
ADMIN_MFA_REQUIRED=true
```

#### `ADMIN_MIN_AAL` (default: `2`)
Minimum Authenticator Assurance Level required.
- `1` - Single factor (password only)
- `2` - Multi-factor (password + TOTP/WebAuthn/etc.)
```bash
ADMIN_MIN_AAL=2
```

#### `ADMIN_STEP_UP_MAX_AGE_SECONDS` (default: `600`)
Maximum age in seconds for authentication events before requiring reauthentication.
```bash
# 10 minutes (default)
ADMIN_STEP_UP_MAX_AGE_SECONDS=600

# 5 minutes (stricter)
ADMIN_STEP_UP_MAX_AGE_SECONDS=300

# 30 minutes (more permissive, not recommended)
ADMIN_STEP_UP_MAX_AGE_SECONDS=1800
```

#### `ALLOWED_ORIGINS`
Comma-separated list of allowed origins for CORS (inherited from shared CORS config).
```bash
ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
```

## Response Behavior

### Success Response (200 OK)
User has valid admin role, AAL2, and recent authentication:
```json
{
  "isAdmin": true,
  "userId": "uuid-here"
}
```

### Step-Up Required (401 Unauthorized)
User lacks MFA or recent authentication:
```json
{
  "isAdmin": false,
  "mfa_required": true,
  "reason": "Multi-factor authentication (AAL2) required for admin access"
}
```

or

```json
{
  "isAdmin": false,
  "mfa_required": true,
  "reason": "Recent authentication required (within 600s)"
}
```

### No Admin Role (200 OK)
User authenticated with MFA but not an admin:
```json
{
  "isAdmin": false,
  "userId": "uuid-here"
}
```

### Invalid/Missing Token (401 Unauthorized)
```json
{
  "isAdmin": false,
  "error": "No authorization header"
}
```

## Security Best Practices

### For Applications Using This Endpoint

1. **Handle `mfa_required` Flag:**
   ```typescript
   const response = await supabase.functions.invoke('check-admin');
   
   if (response.data.mfa_required) {
     // Redirect to MFA enrollment or step-up challenge
     redirectToMfaChallenge();
   } else if (response.data.isAdmin) {
     // Grant admin access
     allowAdminFeatures();
   }
   ```

2. **Implement Step-Up Flow:**
   - Prompt user to reauthenticate when `mfa_required` is true
   - Use Supabase MFA APIs to challenge the user
   - After successful MFA, retry admin check

3. **Cache Admin Status Briefly:**
   - Cache admin status client-side for ~1-2 minutes max
   - Always revalidate before sensitive operations
   - Clear cache on logout or session changes

4. **Configure Appropriate Timeouts:**
   - Balance security vs. user experience
   - Default 10 minutes is reasonable for most applications
   - Consider 5 minutes for highly sensitive operations
   - Never exceed 30 minutes

### For Infrastructure

1. **Set ALLOWED_ORIGINS:**
   Configure only your trusted application origins:
   ```bash
   ALLOWED_ORIGINS=https://app.yourdomain.com,https://admin.yourdomain.com
   ```

2. **Monitor Failed Attempts:**
   - Log failed step-up validations (already implemented)
   - Alert on unusual patterns (many failures from same user/IP)
   - Track `mfa_required` responses for enrollment metrics

3. **Regular Security Audits:**
   - Review admin access logs
   - Verify MFA enrollment rates
   - Test step-up flow regularly

## Testing

### Unit Tests
Run the comprehensive test suite:
```bash
deno test supabase/functions/check-admin/stepup_test.ts
```

Tests cover:
- JWT decoding (valid, malformed, invalid)
- AAL2 detection (aal claim, amr methods, edge cases)
- Recent authentication (auth_time, iat fallback, stale tokens, future timestamps)
- Integration scenarios (full step-up validation)

### Manual Testing

#### Test AAL2 Requirement
```bash
# Without MFA (should fail)
curl -i -X POST https://your-project.supabase.co/functions/v1/check-admin \
  -H "Authorization: Bearer YOUR_AAL1_TOKEN"

# Expected: 401 with mfa_required: true

# With MFA (should succeed if admin)
curl -i -X POST https://your-project.supabase.co/functions/v1/check-admin \
  -H "Authorization: Bearer YOUR_AAL2_TOKEN"

# Expected: 200 with isAdmin: true/false
```

#### Test Recency Requirement
1. Authenticate with MFA
2. Wait longer than `ADMIN_STEP_UP_MAX_AGE_SECONDS`
3. Call check-admin endpoint
4. Expected: 401 with recency error

#### Test CORS
```bash
# From disallowed origin
curl -i -X OPTIONS https://your-project.supabase.co/functions/v1/check-admin \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST"

# Expected: 403 Forbidden

# From allowed origin
curl -i -X OPTIONS https://your-project.supabase.co/functions/v1/check-admin \
  -H "Origin: https://app.yourdomain.com" \
  -H "Access-Control-Request-Method: POST"

# Expected: 204 with CORS headers
```

## Migration Guide

### Existing Applications

If you're upgrading from the previous version without MFA enforcement:

1. **Communicate Changes:**
   - Inform admin users that MFA will be required
   - Provide timeline for enforcement

2. **Enable MFA for Admins:**
   ```typescript
   // Guide admins through MFA enrollment
   const { data, error } = await supabase.auth.mfa.enroll({
     factorType: 'totp'
   });
   ```

3. **Update Client Code:**
   - Handle `mfa_required` response
   - Implement step-up challenge UI
   - Update session refresh logic

4. **Gradual Rollout:**
   - Start with `ADMIN_MFA_REQUIRED=false` and monitor
   - Ensure all admins have MFA enrolled
   - Enable `ADMIN_MFA_REQUIRED=true` in production

5. **Monitor Metrics:**
   - Track MFA enrollment rates
   - Monitor `mfa_required` response frequency
   - Adjust `ADMIN_STEP_UP_MAX_AGE_SECONDS` based on usage patterns

## Compliance

This implementation satisfies:

- ✅ **OWASP A07:2021** - Identification and Authentication Failures
  - Requires strong authentication for privileged operations
  - Enforces MFA for administrative access
  - Validates session freshness

- ✅ **PCI DSS 8.3** - Secure authentication for non-consumer users
  - Multi-factor authentication for administrators
  - Session timeout enforcement
  - Recent authentication requirement

- ✅ **NIST 800-63B** - Digital Identity Guidelines
  - AAL2 enforcement for privileged access
  - Reauthentication for sensitive operations

## Troubleshooting

### "mfa_required: true" for enrolled users

**Cause:** User's current session doesn't have AAL2 indicators.

**Solution:**
1. Have user log out and log in again
2. During login, challenge for MFA
3. New session will include AAL2 claims

### "Recent authentication required" error

**Cause:** User authenticated more than `ADMIN_STEP_UP_MAX_AGE_SECONDS` ago.

**Solution:**
1. Prompt user to reauthenticate
2. Use Supabase step-up challenge flow
3. Consider adjusting timeout if too strict

### Admin check fails immediately after MFA enrollment

**Cause:** Token was issued before MFA enrollment; lacks AAL2 claims.

**Solution:**
1. User must log out and log in again
2. Or trigger a step-up challenge to refresh token
3. Client should handle this gracefully

## References

- [Supabase Multi-Factor Authentication](https://supabase.com/docs/guides/auth/auth-mfa)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/)
- [NIST 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
