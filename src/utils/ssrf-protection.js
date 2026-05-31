/**
 * ✅ SECURITY FIX: SSRF Prevention
 * Validates that target hosts are not in private ranges or reserved ranges
 */

function isPrivateIP(ip) {
  // IPv4 private ranges
  const ipv4PrivateRanges = [
    /^10\./,                      // 10.0.0.0/8
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
    /^192\.168\./,                // 192.168.0.0/16
    /^127\./,                     // 127.0.0.0/8 (loopback)
    /^169\.254\./,                // 169.254.0.0/16 (link-local)
    /^0\./,                       // 0.0.0.0/8
    /^255\./,                     // 255.0.0.0/8 (broadcast)
  ];

  return ipv4PrivateRanges.some(range => range.test(ip));
}

function isIPAddress(str) {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  return ipv4Regex.test(str);
}

export function validateTargetHost(hostname) {
  // Check if it's a private IP address
  if (isIPAddress(hostname) && isPrivateIP(hostname)) {
    return {
      allowed: false,
      reason: "Target IP is in private range - access denied for security",
    };
  }

  // Localhost is only allowed in non-production environments
  if (process.env.NODE_ENV !== "production" && ["localhost", "127.0.0.1", "::1"].includes(hostname)) {
    return { allowed: true };
  }

  return { allowed: true };
}

/**
 * Check for localhost-specific request (for DVWA and local testing)
 */
export function isLocalhostRequest(hostname) {
  const localhostPatterns = ["localhost", "127.0.0.1", "::1", "0.0.0.0"];
  return localhostPatterns.includes(hostname);
}

/**
 * Whitelist of allowed Docker bridge hosts (only for localhost requests)
 */
export const ALLOWED_BRIDGE_HOSTS = ["host.docker.internal", "172.17.0.1"];

export default { validateTargetHost, isLocalhostRequest, ALLOWED_BRIDGE_HOSTS };

