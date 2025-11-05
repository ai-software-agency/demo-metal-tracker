/**
 * Extract client IP address from request headers
 * Checks x-forwarded-for (first IP), cf-connecting-ip, x-real-ip in order
 */
export function getClientIp(req: Request): string {
  // Check x-forwarded-for header (comma-separated list, first is client)
  const forwardedFor = req.headers.get('x-forwarded-for');
  if (forwardedFor) {
    const firstIp = forwardedFor.split(',')[0].trim();
    if (firstIp) return firstIp;
  }

  // Check Cloudflare connecting IP
  const cfIp = req.headers.get('cf-connecting-ip');
  if (cfIp) return cfIp;

  // Check x-real-ip
  const realIp = req.headers.get('x-real-ip');
  if (realIp) return realIp;

  // Fallback to unknown
  return 'unknown';
}
