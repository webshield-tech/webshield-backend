/**
 * XSS/CSRF Scanner — WebShield Vuln Spectra
 * ==========================================
 * Crawls the target page, finds forms and input parameters,
 * tests for reflected XSS, and checks for CSRF protection.
 *
 * Output format (parseable by parseXss()):
 *   XSS_FOUND:<json>   — reflected XSS confirmed
 *   CSRF_FOUND:<json>  — CSRF token missing on form
 *   RESULT: XSS_VULNERABLE / CSRF_VULNERABLE / SAFE
 */

import axios from 'axios';
import * as cheerio from 'cheerio';
import https from 'https';

const XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '"><script>alert(1)</script>',
  "'><img src=x onerror=alert(1)>",
  '<img src=x onerror=alert(1)>',
  'javascript:alert(1)',
  '"><svg onload=alert(1)>',
  '<body onload=alert(1)>',
];

const CSRF_TOKEN_NAMES = [
  '_token', 'csrf_token', 'csrfmiddlewaretoken', '_csrf', 'authenticity_token',
  'csrf', '__RequestVerificationToken', 'xsrf_token', '_csrftoken',
];

const agent = new https.Agent({ rejectUnauthorized: false });

async function fetchPage(url, timeout = 10000) {
  const res = await axios.get(url, {
    httpsAgent: agent,
    timeout,
    maxRedirects: 3,
    headers: { 'User-Agent': 'WebShield-XSS-Scanner/1.0 (Security Audit)' },
    validateStatus: () => true,
  });
  return res;
}

async function testXssReflection(url, paramName, payload) {
  try {
    const testUrl = new URL(url);
    testUrl.searchParams.set(paramName, payload);
    const res = await fetchPage(testUrl.toString(), 8000);
    const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
    // Check if the raw payload is reflected unescaped
    const reflected = body.includes(payload) &&
      !body.includes(`&lt;script`) &&
      !body.includes('&amp;');
    return reflected;
  } catch {
    return false;
  }
}

async function testFormXss(formAction, formMethod, fields, payload) {
  try {
    const params = {};
    for (const field of fields) {
      params[field] = field.toLowerCase().includes('email') ? 'test@test.com' : payload;
    }
    let res;
    if (formMethod === 'post') {
      res = await axios.post(formAction, new URLSearchParams(params).toString(), {
        httpsAgent: agent,
        timeout: 8000,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'WebShield-XSS-Scanner/1.0',
        },
        maxRedirects: 2,
        validateStatus: () => true,
      });
    } else {
      const getUrl = new URL(formAction);
      for (const [k, v] of Object.entries(params)) getUrl.searchParams.set(k, v);
      res = await fetchPage(getUrl.toString(), 8000);
    }
    const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
    return body.includes(payload) && !body.includes('&lt;script') && !body.includes('&amp;');
  } catch {
    return false;
  }
}

async function run() {
  const targetUrl = process.argv[2];
  if (!targetUrl) {
    console.error('[XSS_SCANNER] Target URL required');
    process.exit(1);
  }

  const cleanUrl = targetUrl.replace(/\/+$/, '');
  console.log(`[XSS_SCANNER] Starting XSS/CSRF audit on: ${cleanUrl}`);

  let xssFound = false;
  let csrfFound = false;

  // ── 1. Fetch the target page ─────────────────────────────────────────────
  let pageRes;
  try {
    pageRes = await fetchPage(cleanUrl);
  } catch (e) {
    console.error(`[XSS_SCANNER] Cannot reach target: ${e.message}`);
    console.log('RESULT: SCAN_FAILED (target unreachable)');
    process.exit(0);
  }

  const bodyHtml = typeof pageRes.data === 'string' ? pageRes.data : '';
  const $ = cheerio.load(bodyHtml);
  const baseUrl = cleanUrl;

  // ── 2. Check URL parameters on the page itself ────────────────────────────
  const urlParams = [...new URL(cleanUrl).searchParams.keys()];
  if (urlParams.length > 0) {
    console.log(`[XSS_SCANNER] Testing ${urlParams.length} URL parameter(s) for reflected XSS...`);
    for (const param of urlParams.slice(0, 5)) {
      for (const payload of XSS_PAYLOADS.slice(0, 3)) {
        const reflected = await testXssReflection(cleanUrl, param, payload);
        if (reflected) {
          const finding = { url: cleanUrl, parameter: param, payload, type: 'reflected' };
          console.log(`XSS_FOUND:${JSON.stringify(finding)}`);
          xssFound = true;
          break;
        }
      }
    }
  }

  // ── 3. Find and test all forms ────────────────────────────────────────────
  const forms = [];
  $('form').each((_, el) => {
    const action = $(el).attr('action') || '';
    const method = ($(el).attr('method') || 'get').toLowerCase();
    const inputs = [];
    const hasCsrfToken = CSRF_TOKEN_NAMES.some(name => {
      return $(el).find(`input[name="${name}"], input[name="${name.toUpperCase()}"]`).length > 0;
    });

    $(el).find('input, textarea').each((_, inp) => {
      const name = $(inp).attr('name') || '';
      const type = $(inp).attr('type') || 'text';
      if (name && !['hidden', 'submit', 'button', 'file', 'image', 'reset', 'checkbox', 'radio'].includes(type)) {
        inputs.push(name);
      }
    });

    if (inputs.length > 0) {
      let resolvedAction = action;
      try {
        resolvedAction = action ? new URL(action, baseUrl).toString() : baseUrl;
      } catch { resolvedAction = baseUrl; }
      forms.push({ action: resolvedAction, method, inputs, hasCsrfToken });
    }
  });

  console.log(`[XSS_SCANNER] Found ${forms.length} form(s) to test`);

  for (const form of forms.slice(0, 5)) {
    // CSRF check
    if (form.method === 'post' && !form.hasCsrfToken) {
      const csrfFinding = {
        url: form.action,
        method: form.method,
        issue: 'No CSRF token found in POST form',
        fields: form.inputs,
      };
      console.log(`CSRF_FOUND:${JSON.stringify(csrfFinding)}`);
      csrfFound = true;
    }

    // XSS test on form fields
    if (!xssFound) {
      for (const payload of XSS_PAYLOADS.slice(0, 4)) {
        const reflected = await testFormXss(form.action, form.method, form.inputs, payload);
        if (reflected) {
          const finding = { url: form.action, method: form.method, fields: form.inputs, payload, type: 'reflected_form' };
          console.log(`XSS_FOUND:${JSON.stringify(finding)}`);
          xssFound = true;
          break;
        }
      }
    }
  }

  // ── 4. Check for common search/query parameters ───────────────────────────
  if (!xssFound) {
    const commonParams = ['q', 'search', 'query', 's', 'term', 'keyword', 'name', 'message'];
    for (const param of commonParams) {
      for (const payload of XSS_PAYLOADS.slice(0, 2)) {
        const reflected = await testXssReflection(cleanUrl, param, payload);
        if (reflected) {
          const finding = { url: cleanUrl, parameter: param, payload, type: 'reflected_common' };
          console.log(`XSS_FOUND:${JSON.stringify(finding)}`);
          xssFound = true;
          break;
        }
      }
      if (xssFound) break;
    }
  }

  // ── 5. Summary ────────────────────────────────────────────────────────────
  if (xssFound) {
    console.log('RESULT: XSS_VULNERABLE');
  }
  if (csrfFound) {
    console.log('RESULT: CSRF_VULNERABLE');
  }
  if (!xssFound && !csrfFound) {
    console.log('RESULT: SAFE (No XSS or CSRF vulnerabilities detected)');
  }

  console.log(`[XSS_SCANNER] Scan complete. XSS=${xssFound}, CSRF=${csrfFound}`);
}

run().catch(e => {
  console.error('[XSS_SCANNER] Unexpected error:', e.message);
  console.log('RESULT: SCAN_FAILED');
  process.exit(0);
});
