/**
 * Analyzes Reconnaissance data to determine the optimal tools to run.
 * Upgraded with explainability, confidence scoring, and structured evidence.
 */
export function decideScanPlan(reconData, scanMode = 'deep') {
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

  // Fallback Safety Mechanism
  if (!reconData.isAlive) {
    console.warn("[DecisionEngine] Recon failed or host dead. Engaging fallback safe scan.");
    setDecision('nmap', 'run', 'Core port scanning fallback', 1.0, ['Host HTTP unreachable']);
    setDecision('nuclei', 'run', 'Core vulnerability scanning fallback', 1.0, ['Host HTTP unreachable']);
    
    const skippedTools = ['nikto', 'sqlmap', 'wapiti', 'gobuster', 'ssl', 'dns', 'whois'];
    skippedTools.forEach(t => setDecision(t, 'skip', 'Recon failed, fallback safe scan applied', 1.0, ['Host HTTP unreachable']));
    return plan;
  }

  const { evidence } = reconData;

  // 1. Mandatory Core Tools
  setDecision('nmap', 'run', 'Core port scanning required for all targets', 1.0);
  setDecision('nuclei', 'run', 'Core template-based vulnerability scanning required', 1.0);
  
  // 2. DNS / Whois
  if (scanMode === 'deep') {
    setDecision('dns', 'run', 'Deep scan requested: domain enumeration', 0.9);
    setDecision('whois', 'run', 'Deep scan requested: domain ownership', 0.9);
  } else {
    setDecision('dns', 'skip', 'Skipped in Quick Scan mode to save time', 0.8);
    setDecision('whois', 'skip', 'Skipped in Quick Scan mode to save time', 0.8);
  }

  // 3. Nikto
  if (scanMode === 'quick') {
    setDecision('nikto', 'skip', 'Heavy web scanner skipped in Quick Scan mode', 0.9);
  } else {
    setDecision('nikto', 'run', 'Standard web vulnerability scanner', 0.8);
  }

  // 4. SQLMap Logic
  if (reconData.isStaticFrontend) {
    setDecision('sqlmap', 'skip', 'Static frontend detected (no backend database)', 0.95, evidence.htmlIndicators);
  } else if (reconData.hasInputForms || reconData.hasLoginForm) {
    setDecision('sqlmap', 'run', 'Input forms detected on target', 0.9, [`Forms counted: ${evidence.formCount}`]);
  } else {
    setDecision('sqlmap', 'skip', 'No input forms detected (saves time)', 0.85, ['No <form> elements found']);
  }

  // 5. SSLScan Logic
  if (reconData.hasSSL || reconData.openPorts.includes(443)) {
    setDecision('ssl', 'run', 'HTTPS (port 443) detected', 0.98, ['Port 443 is open or https:// scheme used']);
  } else {
    setDecision('ssl', 'skip', 'No HTTPS port detected', 0.95, ['Only HTTP detected']);
  }

  // 6. Wapiti Logic (XSS/CSRF testing)
  if (scanMode === 'quick') {
    setDecision('wapiti', 'skip', 'Heavy payload scanner skipped in Quick Scan mode', 0.9);
  } else if (reconData.isStaticFrontend) {
    setDecision('wapiti', 'skip', 'Static frontend detected (less relevant for server-side XSS)', 0.9, evidence.htmlIndicators);
  } else if (reconData.hasInputForms) {
    setDecision('wapiti', 'run', 'Input forms detected, testing for XSS/CSRF', 0.85, [`Forms counted: ${evidence.formCount}`]);
  } else {
    setDecision('wapiti', 'skip', 'No input forms detected', 0.85, ['No <form> elements found']);
  }

  // 7. Gobuster (Directory Brute Forcing)
  if (scanMode === 'deep') {
    setDecision('gobuster', 'run', 'Deep scan requested: active directory brute forcing', 0.9);
  } else {
    setDecision('gobuster', 'skip', 'Skipped in Quick Scan mode', 0.95);
  }

  console.log("[DecisionEngine] Smart Plan Generated:", { run: plan.run, skip: plan.skip });
  return plan;
}
