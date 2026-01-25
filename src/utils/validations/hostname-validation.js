export function validateHostname(hostname) {
  // Reject empty
  if (!hostname || hostname.trim() === "") {
    throw new Error("Hostname cannot be empty");
  }

  // Reject too long
  if (hostname.length > 253) {
    throw new Error("Hostname too long");
  }

  // Valid domain regex
  const domainRegex = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$/;

  // Valid IP regex
  const ipv4Regex =
    /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

  // Check if it's a valid domain or IP
  if (!domainRegex.test(hostname) && !ipv4Regex.test(hostname)) {
    throw new Error("Invalid hostname format");
  }

  // Block internal/private IPs and localhost
  const blockedPatterns = [
    "localhost",
    "127.0.0.1",
    "192.168.",
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
  ];

  for (const pattern of blockedPatterns) {
    if (hostname.includes(pattern)) {
      throw new Error("Scanning internal networks is not allowed");
    }
  }

  return hostname;
}
