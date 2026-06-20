/**
 * Analyzes Reconnaissance data to determine the optimal tools to run.
 * Streamlined for low-memory EC2 instances — only essential tools.
 *
 * Active scan tools: nmap, nikto, ssl (sslscan), sqlmap, ffuf
 * Removed from pipeline: gobuster, wapiti, nuclei, ratelimit
 * DNS/WHOIS remain as inline tools only (handled separately).
 */
export function decideScanPlan(reconData, scanMode = 'medium') {
  // normalize incoming scanMode: accept 'full' or legacy 'deep' as full, everything else as medium
  const normalizedMode = (scanMode === 'full' || scanMode === 'deep') ? 'full' : 'medium';

  const plan = {
    run: [],
    skip: [],
    details: {}
  };

  function setDecision(tool, decision, reason, confidence, evidenceList = []) {
    if (decision === 'run') plan.run.push(tool);
    if (decision === 'skip') plan.skip.push(tool);

    plan.details[tool] = {
      decision,
      reason,
      confidence,
      evidence: evidenceList
    };
  }

  // Fallback Safety Mechanism: host unreachable → only nmap
  if (!reconData.isAlive) {
    console.warn('[DecisionEngine] Recon failed or host dead. Engaging fallback safe scan.');
    setDecision('nmap', 'run', 'Core port scanning fallback', 1.0, ['Host HTTP unreachable']);

    const skippedTools = ['nikto', 'sqlmap', 'ssl', 'ffuf'];
    skippedTools.forEach(t =>
      setDecision(t, 'skip', 'Recon failed, fallback safe scan applied', 1.0, ['Host HTTP unreachable'])
    );
    return plan;
  }

  const { evidence } = reconData;
  const dbHints = Array.isArray(reconData.dbIndicators) ? reconData.dbIndicators : [];

  // 1. Nmap — always run (core port/service discovery)
  setDecision('nmap', 'run', 'Core port and service discovery', 1.0);

  // 2. SSL/TLS scan — run only when HTTPS is present
  if (reconData.hasSSL || (Array.isArray(reconData.openPorts) && reconData.openPorts.includes(443))) {
    setDecision('ssl', 'run', 'HTTPS detected — auditing TLS configuration', 0.98, ['Port 443 open or https:// scheme used']);
  } else {
    setDecision('ssl', 'skip', 'No HTTPS detected on target', 0.95, ['Only HTTP detected']);
  }

  // 3. Nikto — always run for non-static sites (web server vulnerability audit)
  if (reconData.isStaticFrontend) {
    setDecision('nikto', 'skip', 'Static frontend detected — no server-side attack surface', 0.9, evidence.htmlIndicators || []);
  } else {
    setDecision('nikto', 'run', 'Web server vulnerability and misconfiguration audit', 0.9);
  }

  // 4. SQLMap — only when backend forms/database indicators are present
  if (reconData.isStaticFrontend) {
    setDecision('sqlmap', 'skip', 'Static frontend — no backend database surface', 0.95, evidence.htmlIndicators || []);
  } else if (reconData.hasInputForms || reconData.hasLoginForm) {
    if (dbHints.length > 0) {
      setDecision('sqlmap', 'run', 'Forms + DB indicators detected — SQL injection testing', 0.95, [
        `Forms found: ${evidence.formCount || '?'}`,
        `DB hints: ${dbHints.join(', ')}`
      ]);
    } else {
      setDecision('sqlmap', 'run', 'Input forms detected — testing for SQL injection', 0.8, [
        `Forms found: ${evidence.formCount || '?'}`
      ]);
    }
  } else {
    setDecision('sqlmap', 'skip', 'No input forms detected — skipping SQL injection test', 0.85, ['No <form> elements found']);
  }

  // 5. FFUF — directory fuzzing for backend targets with backend surface
  if (reconData.isStaticFrontend) {
    setDecision('ffuf', 'skip', 'Static frontend — no hidden backend paths to discover', 0.9, evidence.htmlIndicators || []);
  } else {
    setDecision('ffuf', 'run', 'Fast directory and endpoint discovery', 0.85);
  }

  console.log('[DecisionEngine] Scan Plan:', { run: plan.run, skip: plan.skip });
  return plan;
}
