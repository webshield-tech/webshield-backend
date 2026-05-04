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
    
    const skippedTools = ['nikto', 'sqlmap', 'wapiti', 'gobuster', 'ssl', 'dns', 'ffuf', 'ratelimit', 'xss'];
    skippedTools.forEach(t => setDecision(t, 'skip', 'Recon failed, fallback safe scan applied', 1.0, ['Host HTTP unreachable']));
    return plan;
  }

  const { evidence } = reconData;

  // 1. Mandatory Core Tools
  setDecision('nmap', 'run', 'Core port scanning required for all targets', 1.0);
  setDecision('nuclei', 'run', 'Core template-based vulnerability scanning required', 1.0);
  
  // 2. Web / TLS baseline checks
  if (scanMode === 'quick') {
    setDecision('nikto', 'skip', 'Heavy web scanner skipped in Quick Scan mode', 0.9);
  } else {
    setDecision('nikto', 'run', 'Standard web vulnerability scanner for deep scan', 0.8);
  }

  if (reconData.hasSSL || reconData.openPorts.includes(443)) {
    setDecision('ssl', 'run', 'HTTPS (port 443) detected', 0.98, ['Port 443 is open or https:// scheme used']);
  } else {
    setDecision('ssl', 'skip', 'No HTTPS port detected', 0.95, ['Only HTTP detected']);
  }

  // 3. Input-aware web app checks
  // SQLMap and Wapiti are only useful when the app shows signs of backend or forms.
  if (reconData.isStaticFrontend) {
    setDecision('sqlmap', 'skip', 'Static frontend detected (no backend database)', 0.95, evidence.htmlIndicators);

    if (reconData.hasInputForms || reconData.hasLoginForm) {
      if (scanMode === 'quick') {
        setDecision('wapiti', 'skip', 'Static frontend forms detected, but heavy form crawling is skipped in Quick Scan mode', 0.9, evidence.htmlIndicators);
      } else {
        setDecision('wapiti', 'run', 'Static frontend has forms, so form-aware checks are still useful', 0.85, evidence.htmlIndicators);
      }
      setDecision('xss', 'run', 'Frontend inputs were detected, so reflected XSS and CSRF checks are still relevant', 0.92, evidence.htmlIndicators);
    } else {
      setDecision('wapiti', 'skip', 'Static frontend detected (no forms to test)', 0.95, evidence.htmlIndicators);
      setDecision('xss', 'skip', 'Static frontend detected (no inputs to test)', 0.95, evidence.htmlIndicators);
    }
  } else if (reconData.hasInputForms || reconData.hasLoginForm) {
    setDecision('sqlmap', 'run', 'Input forms detected on target', 0.9, [`Forms counted: ${evidence.formCount}`]);
    setDecision('xss', 'run', 'Forms/inputs detected — testing for XSS and CSRF vulnerabilities', 0.9, [`Forms: ${evidence.formCount}`]);
    if (scanMode === 'quick') {
      setDecision('wapiti', 'skip', 'Heavy payload scanner skipped in Quick Scan mode', 0.9);
    } else {
      setDecision('wapiti', 'run', 'Input forms detected, testing for XSS/CSRF/injection', 0.85, [`Forms counted: ${evidence.formCount}`]);
    }
  } else {
    setDecision('sqlmap', 'skip', 'No input forms detected (saves time)', 0.85, ['No <form> elements found']);
    setDecision('wapiti', 'skip', 'No input forms detected', 0.85, ['No <form> elements found']);
    setDecision('xss', 'skip', 'No input forms or dynamic parameters found', 0.85, ['No <form> elements found']);
  }

  // 4. Rate limit check — decide ONCE based on static frontend flag
  // Do NOT set ratelimit decision multiple times (prevents double-set bug)
  if (reconData.isStaticFrontend) {
    setDecision('ratelimit', 'skip', 'Frontend-only target detected (no backend/API surface)', 0.9, evidence.htmlIndicators);
  } else {
    // For backend sites, include ratelimit in deep mode or if backend is confirmed
    const hasBackendDetected = !reconData.isStaticFrontend && (reconData.hasInputForms || reconData.hasLoginForm);
    if (scanMode === 'deep' || hasBackendDetected) {
      setDecision('ratelimit', 'run', hasBackendDetected ? 'Backend detected: testing API throttling' : 'Deep scan: request throttling check', 0.8);
    } else {
      setDecision('ratelimit', 'skip', 'Skipped in Quick Scan mode for non-backend target', 0.9);
    }
  }

  // 5. Deep discovery / auxiliary checks
  const hasBackendDetected = !reconData.isStaticFrontend && (reconData.hasInputForms || reconData.hasLoginForm);

  if (scanMode === 'deep' || hasBackendDetected) {
    setDecision('gobuster', 'run', hasBackendDetected ? 'Backend detected: running directory discovery' : 'Deep scan requested: active directory brute forcing', 0.9);
    setDecision('ffuf', 'run', hasBackendDetected ? 'Backend detected: running endpoint fuzzing' : 'Deep scan requested: fast fuzzing for hidden endpoints', 0.85);
    setDecision('dns', 'run', hasBackendDetected ? 'Backend detected: running DNS enumeration' : 'Deep scan requested: domain enumeration', 0.9);
  } else {
    setDecision('gobuster', 'skip', 'Skipped in Quick Scan mode', 0.95);
    setDecision('ffuf', 'skip', 'Skipped in Quick Scan mode', 0.9);
    setDecision('dns', 'skip', 'Skipped in Quick Scan mode to save time', 0.8);
  }

  console.log("[DecisionEngine] Smart Plan Generated:", { run: plan.run, skip: plan.skip });
  return plan;
}
