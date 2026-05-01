import axios from 'axios';

async function testRateLimit() {
  const url = process.argv[2];
  if (!url) {
    console.error("URL required");
    process.exit(1);
  }

  const cleanUrl = url.replace(/\/+$/, "");
  console.log(`[STRESS_TEST] Target: ${cleanUrl}`);
  
  // 1. API Activity Check
  const apiPaths = ["/api", "/v1", "/graphql", "/api/v1", "/rest"];
  const apiStatus = [];
  
  console.log("[API_CHECK] Probing common API endpoints...");
  for (const path of apiPaths) {
    try {
      const res = await axios.get(`${cleanUrl}${path}`, { timeout: 3000, validateStatus: () => true });
      if (res.status !== 404) {
        apiStatus.push({ path, status: res.status });
      }
    } catch (e) {}
  }

  if (apiStatus.length > 0) {
    console.log(`RESULT: API_ACTIVE (Found ${apiStatus.length} endpoints: ${apiStatus.map(a => a.path).join(", ")})`);
  } else {
    console.log("RESULT: API_NOT_DETECTED (Standard API paths returned 404)");
  }

  // 2. Burst Rate Limit Test
  console.log("[BURST_TEST] Launching 100 concurrent requests to test rate limiting...");
  const requests = [];
  const start = Date.now();
  
  for (let i = 0; i < 100; i++) {
    requests.push(
      axios.get(cleanUrl, { 
        timeout: 10000, 
        validateStatus: () => true,
        headers: { 'User-Agent': 'WebShield-Stress-Tester/2.0' }
      }).catch(e => ({ status: 'error', message: e.message }))
    );
  }

  const results = await Promise.all(requests);
  const duration = Date.now() - start;
  
  const statusCodes = results.map(r => r.status);
  const count429 = statusCodes.filter(s => s === 429).length;
  const countSuccess = statusCodes.filter(s => s >= 200 && s < 300).length;
  const countForbidden = statusCodes.filter(s => s === 403).length;
  
  console.log(`[STATS] Duration: ${duration}ms | Success: ${countSuccess} | RateLimited(429): ${count429} | Blocked(403): ${countForbidden}`);

  if (count429 > 0) {
    console.log("RESULT: RATE_LIMIT_ACTIVE (Server returned 429 Too Many Requests)");
  } else if (countForbidden > 20) {
    console.log("RESULT: REQUEST_LIMITER_ACTIVE (WAF/Firewall blocked multiple requests with 403)");
  } else if (countSuccess > 90) {
    console.log("RESULT: NO_LIMITER_DETECTED (Server accepted all burst traffic)");
  } else {
    console.log("RESULT: INCONCLUSIVE (High error rate or inconsistent responses)");
  }
}

testRateLimit();
