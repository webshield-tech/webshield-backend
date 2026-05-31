export function validateHostname(hostname, options = {}) {
  // Reject empty
  if (!hostname || hostname.trim() === '') {
    throw new Error('Hostname cannot be empty');
  }
  
  // Reject too long
  if (hostname.length > 253) {
    throw new Error('Hostname too long');
  }
  
  // Valid domain regex
  const domainRegex = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$/;
  
  // Valid IP regex
  const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  
  // Check if it's a valid domain or IP
  if (!domainRegex.test(hostname) && !ipv4Regex.test(hostname)) {
    throw new Error('Invalid hostname format');
  }
  
  const allowLocalTargets =
    String(
      process.env.ALLOW_LOCAL_TARGETS ??
        (process.env.NODE_ENV === "production" ? "false" : "true")
    )
      .trim()
      .toLowerCase() === "true";

  const normalizedPort = String(options.port ?? "").trim();
  const demoLoopbackPorts = new Set(["80", "443", "8080"]);
  const demoLoopbackHosts = new Set([
    "localhost",
    "127.0.0.1",
    "::1",
    "host.docker.internal",
  ]);
  const isDemoLoopbackTarget =
    !allowLocalTargets &&
    demoLoopbackPorts.has(normalizedPort) &&
    demoLoopbackHosts.has(hostname.toLowerCase());

  // Block internal/private IPs and localhost (unless explicitly enabled for local demo)
  const isIPv4 = ipv4Regex.test(hostname);

  if (!allowLocalTargets) {
    const lowerHostname = hostname.toLowerCase();

    // If it's an IP address, match known private ranges precisely
    if (isIPv4) {
      if (
        lowerHostname.startsWith('10.') ||
        lowerHostname.startsWith('192.168.') ||
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(lowerHostname) ||
        lowerHostname.startsWith('127.') ||
        lowerHostname.startsWith('169.254.') ||
        lowerHostname.startsWith('0.')
      ) {
        if (isDemoLoopbackTarget) return hostname;
        throw new Error('Scanning internal networks is not allowed');
      }
    } else {
      // For hostnames, only block exact local hostnames used for loopback or docker bridge
      if (demoLoopbackHosts.has(lowerHostname)) {
        if (isDemoLoopbackTarget) return hostname;
        throw new Error('Scanning internal networks is not allowed');
      }
    }
  }
  
  return hostname;
}
