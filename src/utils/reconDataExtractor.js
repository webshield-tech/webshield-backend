import axios from 'axios';
import * as cheerio from 'cheerio';
import https from 'https';
import { runWhatWeb } from './scanners/whatweb-scanner.js';

/**
 * Performs lightweight reconnaissance on a target URL before running aggressive scans.
 * Extracts data and evidence to feed into the scan decision engine.
 */
export async function extractReconData(targetUrl) {
  const timeoutMs = Number(process.env.RECON_TIMEOUT_MS || 15000);
  const reconData = {
    hasLoginForm: false,
    hasInputForms: false,
    hasSSL: targetUrl.startsWith('https://'),
    platform: null,
    technologies: [],
    openPorts: [],
    isAlive: false,
    isStaticFrontend: false,
    dbIndicators: [], // e.g., ['mysql','postgresql']
    hasDatabase: false,
    evidence: {
      headers: {},
      htmlIndicators: [],
      formCount: 0
    }
  };

  try {
    const parsedUrl = new URL(targetUrl);
    const httpsAgent = new https.Agent({ rejectUnauthorized: false });
    
    console.log(`[Recon] Starting scout phase for ${targetUrl}`);
    const response = await axios.get(targetUrl, {
      httpsAgent,
      timeout: timeoutMs,
      maxRedirects: 3,
    });

    reconData.isAlive = true;

    // 1. Analyze HTML
    const $ = cheerio.load(response.data);
    
    const forms = $('form');
    reconData.evidence.formCount = forms.length;
    reconData.hasInputForms = forms.length > 0;

    const passwordInputs = $('input[type="password"]');
    if (passwordInputs.length > 0) {
      reconData.hasLoginForm = true;
      reconData.evidence.htmlIndicators.push('Password input detected');
    }

    if (forms.length > 0) {
      reconData.evidence.htmlIndicators.push(`Found ${forms.length} <form> tag(s)`);
    } else {
      reconData.evidence.htmlIndicators.push('No <form> tags found on homepage');
    }

    // 2. Analyze Headers & Tech
    const headers = response.headers;
    reconData.evidence.headers = {
      server: headers['server'] || 'Unknown',
      'x-powered-by': headers['x-powered-by'] || 'Unknown'
    };
    
    if (headers['server']) reconData.technologies.push(headers['server'].toLowerCase());
    if (headers['x-powered-by']) reconData.technologies.push(headers['x-powered-by'].toLowerCase());

    // Try to enrich with WhatWeb (conservative aggression). Not fatal if missing.
    let whatwebTechs = [];
    try {
      const ww = await runWhatWeb(targetUrl, Number(process.env.WHATWEB_TIMEOUT_MS || 8000));
      if (ww && Array.isArray(ww.techs) && ww.techs.length) {
        whatwebTechs = ww.techs.map((t) => String(t).toLowerCase());
        reconData.technologies.push(...whatwebTechs);
        reconData.evidence.htmlIndicators.push(`WhatWeb detected: ${whatwebTechs.join(', ')}`);
      }
    } catch (wwErr) {
      // Do not fail recon if whatweb is unavailable or errors
      console.warn('[Recon] WhatWeb probe failed:', wwErr?.message || wwErr);
    }

    // 3. Static / Frontend-only detection
    const serverHeader = (headers['server'] || '').toLowerCase();
    const xPoweredBy = (headers['x-powered-by'] || '').toLowerCase();
    const bodyStr = response.data.toLowerCase();
    
    // ✅ IMPROVED: Better backend detection
    // Check for backend server signatures (real servers, not CDNs)
    const hasBackendSignature = (
      serverHeader.includes('apache') ||
      serverHeader.includes('nginx') ||
      serverHeader.includes('express') ||
      serverHeader.includes('django') ||
      serverHeader.includes('rails') ||
      serverHeader.includes('tomcat') ||
      serverHeader.includes('microsoft-iis') ||
      xPoweredBy.includes('express') ||
      xPoweredBy.includes('django') ||
      xPoweredBy.includes('rails') ||
      xPoweredBy.includes('php') ||
      xPoweredBy.includes('java') ||
      bodyStr.includes('csrf') || // CSRF tokens indicate backend
      bodyStr.includes('authenticity') ||
      // WhatWeb-derived indicators
      whatwebTechs.some(t => ['php','wordpress','mysql','mariadb','postgresql','django','rails','laravel','node.js','node','express','mongodb'].includes(t))
    );
    
    // Static/JAMstack detection - requires a REAL platform signature (not just id="root")
    // id="root" and id="app" are used by every React/Vue app, including full-stack ones with a backend
    const hasPlatformSignature = (
      serverHeader.includes('vercel') ||
      serverHeader.includes('netlify') ||
      serverHeader.includes('github.io') ||
      xPoweredBy.includes('gatsby') ||
      bodyStr.includes('__next_data__') ||
      bodyStr.includes('__nuxt')
    );
    
    // Only call it static if:
    // 1. NO backend server signature detected
    // 2. Platform signature CONFIRMS static hosting
    // 3. NO forms/inputs on homepage
    if (hasPlatformSignature && !reconData.hasInputForms && !hasBackendSignature) {
      reconData.isStaticFrontend = true;
      reconData.evidence.htmlIndicators.push('Static JAMstack/Frontend confirmed by platform signature');
    } else if (hasBackendSignature) {
      reconData.evidence.htmlIndicators.push(`Backend server detected: ${serverHeader || xPoweredBy || 'Dynamic backend'}`);
    } else if (hasPlatformSignature && reconData.hasInputForms) {
      // Platform signature found but forms exist — could be static with embedded forms (e.g. Netlify Forms)
      // Don't mark as static to ensure we test the forms
      reconData.evidence.htmlIndicators.push('JAMstack platform detected but forms found — treating as dynamic');
    }

    // Detect CMS
    if (
      bodyStr.includes('wp-content') || 
      $('meta[name="generator"]').attr('content')?.toLowerCase().includes('wordpress') ||
      whatwebTechs.some(t => t === 'wordpress')
    ) {
      reconData.platform = 'wordpress';
      reconData.technologies.push('wordpress');
      reconData.evidence.htmlIndicators.push('WordPress paths/meta tags or WhatWeb signature found');
    }

    // 4. Port inference
    if (parsedUrl.protocol === 'http:') reconData.openPorts.push(80);
    if (parsedUrl.protocol === 'https:') reconData.openPorts.push(443);

    // --- Lightweight DB port probe (nmap if available, otherwise TCP connect) ---
    try {
      const hostname = parsedUrl.hostname;
      const dbPorts = [3306, 5432, 27017];
      let openPortsFound = [];

      // Try nmap first (fast targeted scan) if binary exists
      const hasNmap = await (async () => {
        try {
          await import('child_process').then((mod) => mod.execSync('command -v nmap', { stdio: 'ignore' }));
          return true;
        } catch {
          return false;
        }
      })();

      if (hasNmap) {
        try {
          const { spawn } = await import('child_process');
          const args = ['-Pn', '-p', dbPorts.join(','), '--open', '-T4', hostname];
          const child = spawn('nmap', args, { stdio: ['ignore', 'pipe', 'pipe'] });
          let out = '';
          let err = '';
          const timeout = setTimeout(() => { try { child.kill('SIGTERM'); } catch (e) {} }, Number(process.env.NMAP_DB_PROBE_TIMEOUT_MS || 8000));
          child.stdout.on('data', (b) => (out += String(b)));
          child.stderr.on('data', (b) => (err += String(b)));
          await new Promise((resolve) => child.on('close', resolve));
          clearTimeout(timeout);
          const lower = out.toLowerCase() + '\n' + err.toLowerCase();
          for (const p of dbPorts) {
            if (lower.includes(`${p}/tcp open`)) openPortsFound.push(p);
          }
        } catch (e) {
          console.warn('[Recon] Nmap DB probe failed:', e?.message || e);
        }
      }

      // Fallback: simple TCP connect if no nmap or nmap failed
      if (!openPortsFound.length) {
        const net = await import('net');
        const attempts = dbPorts.map((p) =>
          new Promise((resolve) => {
            const s = new net.Socket();
            let done = false;
            const to = setTimeout(() => { try { s.destroy(); } catch (e) {} if (!done) { done = true; resolve(false); } }, Number(process.env.TCP_DB_PROBE_TIMEOUT_MS || 1200));
            s.once('error', () => { clearTimeout(to); if (!done) { done = true; resolve(false); } });
            s.connect(p, parsedUrl.hostname, () => { clearTimeout(to); try { s.destroy(); } catch (e) {} if (!done) { done = true; resolve(true); } });
          }).then((ok) => (ok ? p : null))
        );
        const results = await Promise.all(attempts);
        for (const r of results) if (r) openPortsFound.push(r);
      }

      if (openPortsFound.length) {
        reconData.openPorts.push(...openPortsFound);
        reconData.dbIndicators.push(...openPortsFound.map((p) => `port:${p}`));
        reconData.evidence.htmlIndicators.push(`DB ports open: ${openPortsFound.join(', ')}`);
      }

    } catch (portErr) {
      console.warn('[Recon] DB port probe error:', portErr?.message || portErr);
    }

    // 5. Targeted form probes & input heuristics
    try {
      const forms = $('form');
      for (let i = 0; i < forms.length; i++) {
        const form = forms.eq(i);
        const action = form.attr('action') || parsedUrl.href;
        const inputs = form.find('input,textarea,select');
        const inputNames = [];
        inputs.each((idx, el) => { const name = (el.attribs && el.attribs.name) ? String(el.attribs.name).toLowerCase() : ''; if (name) inputNames.push(name); });
        if (inputNames.length) {
          reconData.evidence.htmlIndicators.push(`Form inputs: ${inputNames.slice(0,6).join(', ')}`);
          if (inputNames.some(n => /(^|_)id$|\bid\b|user|username|email|pass|password/.test(n))) {
            reconData.evidence.htmlIndicators.push('Form-like input names detected (id/username/password) — candidate injection points');
          }
        }

        // Probe the action endpoint lightly (HEAD then GET if HEAD not allowed)
        try {
          const probeUrl = new URL(action, parsedUrl.href).href;
          const cfg = { timeout: 3000, maxRedirects: 2, validateStatus: () => true };
          const head = await axios.request({ method: 'HEAD', url: probeUrl, ...cfg, ...(probeUrl.startsWith('https:') ? { httpsAgent: new https.Agent({ rejectUnauthorized: false }) } : {}) });
          if (head && head.status && head.status < 400) {
            reconData.evidence.htmlIndicators.push(`Form action reachable: ${probeUrl} (HEAD ${head.status})`);
          } else {
            const get = await axios.request({ method: 'GET', url: probeUrl, ...cfg, ...(probeUrl.startsWith('https:') ? { httpsAgent: new https.Agent({ rejectUnauthorized: false }) } : {}) });
            if (get && get.status && get.status < 400) reconData.evidence.htmlIndicators.push(`Form action reachable: ${probeUrl} (GET ${get.status})`);
            if (get && typeof get.data === 'string' && /mysql|postgres|mongodb|sql|query\(|select\s+\*/i.test(String(get.data).slice(0, 800))) {
              reconData.evidence.htmlIndicators.push('Form action response contains DB-like keywords');
              reconData.dbIndicators.push('http:body-db-indicator');
            }
          }
        } catch (probeErr) {
          // ignore
        }
      }
    } catch (formErr) {
      console.warn('[Recon] Form probing failed:', formErr?.message || formErr);
    }

    // Consolidate DB indicators from WhatWeb & body
    try {
      const lowerBody = (response.data || '').toLowerCase();
      const dbKeywords = ['mysql','mariadb','postgres','postgresql','mongodb','redis'];
      for (const k of dbKeywords) {
        if (lowerBody.includes(k) && !reconData.dbIndicators.includes(k)) {
          reconData.dbIndicators.push(k);
          reconData.evidence.htmlIndicators.push(`Page contains DB keyword: ${k}`);
        }
      }

      // If whatweb techs indicated DBs earlier, they were pushed into reconData.technologies
      const techsLower = reconData.technologies.map(String).join(',');
      for (const k of ['mysql','postgres','mongodb','mariadb']) {
        if (techsLower.includes(k) && !reconData.dbIndicators.includes(k)) {
          reconData.dbIndicators.push(k);
          reconData.evidence.htmlIndicators.push(`WhatWeb tech hint: ${k}`);
        }
      }

      if (reconData.dbIndicators.length) reconData.hasDatabase = true;
    } catch (consolErr) {
      // ignore
    }

    // Filter duplicates
    reconData.technologies = [...new Set(reconData.technologies)];
    reconData.openPorts = [...new Set(reconData.openPorts)];
    reconData.dbIndicators = [...new Set(reconData.dbIndicators)];

  } catch (error) {
    console.error(`[Recon] Failed to extract data from ${targetUrl}:`, error.message);
    // Return safe default object indicating host is unreachable via HTTP
  }

  return reconData;
}
