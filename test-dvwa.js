const axios = require('axios');

function extractDvwaToken(html = "") {
  const match = String(html).match(/name=['"]user_token['"]\s+value=['"]([^'"]+)['"]/i);
  return match ? match[1] : "";
}

function applySetCookie(cookieJar, setCookieHeaders = []) {
  for (const cookieLine of setCookieHeaders || []) {
    const kv = String(cookieLine).split(";")[0];
    const idx = kv.indexOf("=");
    if (idx <= 0) continue;
    const key = kv.slice(0, idx).trim();
    const val = kv.slice(idx + 1).trim();
    if (key) cookieJar[key] = val;
  }
}

function buildCookieHeader(cookieJar) {
  return Object.entries(cookieJar)
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
}

async function prepareDvwaSqlmapContext(finalUrl) {
  const parsed = new URL(finalUrl);
  const origin = `${parsed.protocol}//${parsed.host}`;
  const cfg = {
    timeout: 12000,
    validateStatus: () => true,
    maxRedirects: 2,
  };

  const probe = await axios.get(`${origin}/login.php`, cfg);
  if (!/Damn Vulnerable Web Application/i.test(String(probe.data || ""))) {
    console.log("Not DVWA");
    return null;
  }

  const jar = {};

  const loginPage = await axios.get(`${origin}/login.php`, {
    ...cfg,
    headers: { Cookie: buildCookieHeader(jar) },
  });
  applySetCookie(jar, loginPage.headers?.["set-cookie"] || []);
  const loginToken = extractDvwaToken(loginPage.data);
  if (loginToken) {
    const loginResp = await axios.post(
      `${origin}/login.php`,
      new URLSearchParams({
        username: "admin",
        password: "password",
        Login: "Login",
        user_token: loginToken,
      }).toString(),
      {
        ...cfg,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: buildCookieHeader(jar),
        },
      }
    );
    applySetCookie(jar, loginResp.headers?.["set-cookie"] || []);
  }

  const securityPage = await axios.get(`${origin}/security.php`, {
    ...cfg,
    headers: { Cookie: buildCookieHeader(jar) },
  });
  applySetCookie(jar, securityPage.headers?.["set-cookie"] || []);
  const secToken = extractDvwaToken(securityPage.data);
  if (secToken) {
    const secResp = await axios.post(
      `${origin}/security.php`,
      new URLSearchParams({
        security: "low",
        seclev_submit: "Submit",
        user_token: secToken,
      }).toString(),
      {
        ...cfg,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: buildCookieHeader(jar),
        },
      }
    );
    applySetCookie(jar, secResp.headers?.["set-cookie"] || []);
  }

  return buildCookieHeader(jar);
}

prepareDvwaSqlmapContext("http://localhost:8080/").then(c => console.log("Cookies:", c));
