import axios from 'axios';

async function testRateLimit() {
  const url = process.argv[2];
  if (!url) {
    console.error("URL required");
    process.exit(1);
  }

  console.log(`Starting Rate Limit Test on: ${url}`);
  const requests = [];
  const start = Date.now();
  
  // Send 50 requests as fast as possible
  for (let i = 0; i < 50; i++) {
    requests.push(
      axios.get(url, { 
        timeout: 5000, 
        validateStatus: () => true,
        headers: { 'User-Agent': 'WebShield-Security-Scanner/1.0' }
      }).catch(e => ({ status: 'error', message: e.message }))
    );
  }

  const results = await Promise.all(requests);
  const duration = Date.now() - start;
  
  const statusCodes = results.map(r => r.status);
  const count429 = statusCodes.filter(s => s === 429).length;
  const countSuccess = statusCodes.filter(s => s >= 200 && s < 300).length;
  const countErrors = statusCodes.filter(s => s === 'error').length;

  console.log(`Test Finished in ${duration}ms`);
  console.log(`Total Requests: 50`);
  console.log(`HTTP 2xx: ${countSuccess}`);
  console.log(`HTTP 429: ${count429}`);
  console.log(`Errors: ${countErrors}`);

  if (count429 > 0) {
    console.log("RESULT: RATE_LIMIT_DETECTED");
  } else if (countSuccess === 50) {
    console.log("RESULT: NO_RATE_LIMIT_DETECTED (Server accepted all 50 requests)");
  } else {
    console.log("RESULT: INCONCLUSIVE (Server returned mixed non-429 errors)");
  }
}

testRateLimit();
