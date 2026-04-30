import dns from "dns";
import { promisify } from "util";

const resolveAny = promisify(dns.resolveAny);
const lookup = promisify(dns.lookup);

async function verifyDns() {
  const hostname = process.argv[2];
  if (!hostname) {
    console.error("Hostname required");
    process.exit(1);
  }

  const results = {};

  try {
    console.log(`Analyzing DNS for: ${hostname}`);
    
    // IP Lookup
    try {
      const addr = await lookup(hostname, { all: true });
      results.ipAddresses = addr.map(a => a.address);
    } catch (e) {
      results.ipLookupError = e.message;
    }

    // Common Records
    const recordTypes = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"];
    for (const type of recordTypes) {
      try {
        const records = await promisify(dns.resolve)(hostname, type);
        results[type] = records;
      } catch (e) {
        // Record might not exist, skip
      }
    }

    console.log(JSON.stringify(results, null, 2));
  } catch (error) {
    console.error("DNS Verification Error:", error.message);
    process.exit(1);
  }
}

verifyDns();
