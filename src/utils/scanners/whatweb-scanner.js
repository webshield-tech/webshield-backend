import { spawn } from 'child_process';

/**
 * Run whatweb with conservative aggression and parse common technology markers.
 * Uses spawn with args (no shell) to avoid injection. Returns an object with
 * techs: array of detected keywords and rawOutput: captured stdout/stderr.
 */
export function runWhatWeb(targetUrl, timeoutMs = 10000) {
  return new Promise((resolve) => {
    try {
      const aggression = String(process.env.WHATWEB_AGGRESSION || '2');
      // aggression: 1-5; default 2 (conservative but thorough)
      const args = ['--no-errors', '-a', aggression, '--log-json', '-', targetUrl];
      const child = spawn('whatweb', args, { stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';
      let finished = false;

      const killTimer = setTimeout(() => {
        try { child.kill('SIGTERM'); } catch (e) {}
      }, timeoutMs);

      child.stdout.on('data', (b) => { stdout += String(b); });
      child.stderr.on('data', (b) => { stderr += String(b); });

      child.on('close', () => {
        if (killTimer) clearTimeout(killTimer);
        finished = true;
        const raw = (stdout || stderr).trim();
        const techs = parseWhatWebOutput(raw);
        resolve({ techs, rawOutput: raw });
      });

      child.on('error', (err) => {
        if (killTimer) clearTimeout(killTimer);
        if (!finished) {
          const raw = (stdout || stderr || err.message || '').trim();
          const techs = parseWhatWebOutput(raw);
          resolve({ techs, rawOutput: raw, error: err.message });
        }
      });
    } catch (err) {
      const msg = String(err?.message || err || 'whatweb-error');
      const techs = parseWhatWebOutput(msg);
      resolve({ techs, rawOutput: msg, error: err?.message });
    }
  });
}

function parseWhatWebOutput(text) {
  if (!text || typeof text !== 'string') return [];
  const lower = text.toLowerCase();
  const candidates = new Set();

  const checks = [
    ['wordpress', ['wordpress','wp-content','wp-'] ],
    ['drupal', ['drupal'] ],
    ['joomla', ['joomla'] ],
    ['php', ['php','php/'] ],
    ['node.js', ['node.js','express','next.js','nuxt','vercel'] ],
    ['django', ['django'] ],
    ['flask', ['flask'] ],
    ['laravel', ['laravel'] ],
    ['ruby on rails', ['rails','ruby on rails'] ],
    ['mysql', ['mysql','mariadb'] ],
    ['postgresql', ['postgresql','postgres'] ],
    ['mongodb', ['mongodb'] ],
    ['iis', ['iis','microsoft-iis'] ],
    ['cloudflare', ['cloudflare'] ],
    ['waf', ['mod_security','waf','web application firewall'] ],
  ];

  for (const [label, keys] of checks) {
    for (const k of keys) {
      if (lower.includes(k)) {
        candidates.add(label);
        break;
      }
    }
  }

  return Array.from(candidates);
}
