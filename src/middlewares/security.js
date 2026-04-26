
export const injectionDetector = (req, res, next) => {
  const sqliPatterns = [
    /'OR\s+'\d+'\s*=\s*'\d+'/i,
    /--/i,
    /;\s*DROP/i,
    /UNION\s+SELECT/i,
    /admin'\s*--/i
  ];

  const body = JSON.stringify(req.body);
  const query = JSON.stringify(req.query);
  const params = JSON.stringify(req.params);

  const allInputs = body + query + params;

  if (sqliPatterns.some(pattern => pattern.test(allInputs))) {
    console.warn(`[SECURITY] Injection attempt detected from IP: ${req.ip}`);
    return res.status(403).json({
      success: false,
      error: "Nice try! Our developers are one step ahead. Injection attempts are blocked and logged.",
      type: "injection_blocked"
    });
  }

  next();
};
