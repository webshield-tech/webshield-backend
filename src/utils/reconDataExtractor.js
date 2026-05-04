import axios from 'axios';
import * as cheerio from 'cheerio';
import https from 'https';

/**
 * Performs lightweight reconnaissance on a target URL before running aggressive scans.
 * Extracts data and evidence to feed into the scan decision engine.
 */
export async function extractReconData(targetUrl) {
  const reconData = {
    hasLoginForm: false,
    hasInputForms: false,
    hasSSL: targetUrl.startsWith('https://'),
    platform: null,
    technologies: [],
    openPorts: [],
    isAlive: false,
    isStaticFrontend: false,
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
      timeout: 10000,
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

    // 3. Static / Frontend-only detection
    const serverHeader = (headers['server'] || '').toLowerCase();
    const xPoweredBy = (headers['x-powered-by'] || '').toLowerCase();
    const bodyStr = response.data.toLowerCase();
    
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
    
    // Only call it static if the hosting platform CONFIRMS it's a static deploy
    // AND there are no forms/inputs (which would indicate a backend exists)
    if (hasPlatformSignature && !reconData.hasInputForms) {
      reconData.isStaticFrontend = true;
      reconData.evidence.htmlIndicators.push('Static JAMstack/Frontend confirmed by platform signature');
    } else if (hasPlatformSignature && reconData.hasInputForms) {
      // Platform signature found but forms exist — could be static with embedded forms (e.g. Netlify Forms)
      // Don't mark as static to ensure we test the forms
      reconData.evidence.htmlIndicators.push('JAMstack platform detected but forms found — treating as dynamic');
    }

    // Detect CMS
    if (
      bodyStr.includes('wp-content') || 
      $('meta[name="generator"]').attr('content')?.toLowerCase().includes('wordpress')
    ) {
      reconData.platform = 'wordpress';
      reconData.technologies.push('wordpress');
      reconData.evidence.htmlIndicators.push('WordPress paths/meta tags found');
    }

    // 4. Port inference
    if (parsedUrl.protocol === 'http:') reconData.openPorts.push(80);
    if (parsedUrl.protocol === 'https:') reconData.openPorts.push(443);

    // Filter duplicates
    reconData.technologies = [...new Set(reconData.technologies)];
    reconData.openPorts = [...new Set(reconData.openPorts)];

  } catch (error) {
    console.error(`[Recon] Failed to extract data from ${targetUrl}:`, error.message);
    // Return safe default object indicating host is unreachable via HTTP
  }

  return reconData;
}
