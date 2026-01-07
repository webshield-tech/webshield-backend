export function urlValidation(input) {
  if (!input || !input.trim()) return { valid: false, error: 'URL is required' };

  let url = input.trim();
  // Add scheme if missing for parsing
  if (!/^https?:\/\//i.test(url)) {
    url = 'https://' + url;
  }

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;
    if (!/^[a-zA-Z0-9.-]+$/.test(hostname) || /[\.\-]{2,}/.test(hostname) || hostname.startsWith('-') || hostname.endsWith('-')) {
  return { valid: false, error: 'Invalid hostname (only letters, numbers, dots, hyphens allowed; no consecutive dots/hyphens or leading/trailing hyphens)' };
}
    // Optionally block very short hostnames
    if (hostname.length < 3) return { valid: false, error: 'Hostname too short' };

    return { valid: true, url: parsed.href };
  } catch (err) {
    return { valid: false, error: 'Invalid URL format' };
  }
}