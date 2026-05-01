import { GoogleGenerativeAI } from '@google/generative-ai';
import dotenv from 'dotenv';
dotenv.config();

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API);
// gemini-2.5-flash has a large context window, so we never have to worry about 413s
const model = genAI.getGenerativeModel({ model: 'gemini-2.5-flash' });

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function normalizeLanguage(language) {
  const value = String(language || 'english').trim().toLowerCase();
  if (['urdu', 'hindi', 'arabic', 'english'].includes(value)) return value;
  return 'english';
}

function stripJsonFences(text = '') {
  return text
    .replace(/^```json\s*/im, '')
    .replace(/^```\s*/im, '')
    .replace(/```\s*$/im, '')
    .trim();
}

function buildFallbackAnalysis(scanInputData) {
  return {
    summary: {
      risk_score: 0,
      overall_status: 'Informational',
      confidence_score: 0.0,
      scan_quality: scanInputData?.scan_type === 'deep' ? 'Deep Scan' : 'Quick Scan',
      key_message: 'AI analysis could not be completed. Please review the raw scan data below.',
    },
    attack_surface: {
      open_ports: scanInputData?.scan_results?.nmap?.open_ports || [],
      directories_found: scanInputData?.scan_results?.gobuster?.directories || [],
      technologies_detected: scanInputData?.detected_technologies || [],
    },
    findings: [],
    informational_findings: [
      {
        title: 'Raw Data Available',
        description: 'AI analysis failed, but raw tool output is available for manual review.',
      },
    ],
    prioritized_actions: ['Review raw scan logs', 'Retry AI analysis later'],
    final_recommendation: 'Manual review required due to AI service disruption.',
  };
}

// ---------------------------------------------------------------------------
// Main AI Correlated Analysis Engine (Structured JSON)
// ---------------------------------------------------------------------------

export async function analyzeVulnerabilities(scanInputData, language = 'english') {
  const normalizedLanguage = normalizeLanguage(language);

  const systemPrompt = `You are a senior penetration tester, cybersecurity analyst, and vulnerability management engine for Vuln Spectra (WebShield).
Your role is to analyze combined scan results from multiple security tools and produce a professional, structured JSON vulnerability assessment.

CORE RULES & CORRELATION LOGIC:
1. Identify REAL vulnerabilities only. Eliminate false positives.
2. DO NOT treat open standard ports (e.g., 80, 443) as vulnerabilities. Mark them Informational.
3. Merge duplicate findings: If multiple tools report the same issue, combine them into one finding.
4. Scale Confidence: 
   - If multiple tools confirm (e.g., SQLMap + Nuclei), increase confidence and list in detection_sources.
   - If weak evidence or single tool (e.g., Nikto version inference), reduce severity/confidence.
5. Provide a realistic risk score (0-100).
6. Output MUST be in ${normalizedLanguage}.

OUTPUT FORMAT — STRICT JSON ONLY:
{
  "summary": {
    "risk_score": <0-100>,
    "overall_status": "<Safe | Informational | Low Risk | Medium Risk | High Risk | Critical>",
    "confidence_score": <0.0-1.0>,
    "scan_quality": "<Quick Scan | Deep Scan>",
    "key_message": "<Short summary>"
  },
  "attack_surface": {
    "open_ports": ["<port/protocol>"],
    "directories_found": ["<path>"],
    "technologies_detected": ["<tech>"]
  },
  "findings": [
    {
      "title": "<Name>",
      "severity": "<Low|Medium|High|Critical>",
      "confidence": <0.0-1.0>,
      "confidence_reason": "<Why is the confidence high or low?>",
      "detection_sources": ["<Tool 1>", "<Tool 2>"],
      "exploitability": "<Easy | Moderate | Hard>",
      "fix_priority": "<Low|Medium|High>",
      "description": "<Explanation>",
      "impact": "<Attacker capability>",
      "evidence": "<Proof>",
      "affected_area": "<URL/port>",
      "recommendation": "<Fix>",
      "platform_specific_fix": "<Fix for detected platform>",
      "references": ["<CVE/CWE>"]
    }
  ],
  "informational_findings": [{"title": "...", "description": "..."}],
  "prioritized_actions": ["<Step 1>", "<Step 2>"],
  "final_recommendation": "<Advice>"
}`;

  try {
    // We use responseMimeType to force JSON output natively (Gemini feature)
    const chatSession = model.startChat({
      generationConfig: {
        temperature: 0.2,
        responseMimeType: "application/json",
      },
    });

    // Gemini 1.5 has 1M token limit, so we don't need to compress the payload!
    const payload = JSON.stringify(scanInputData);
    const prompt = `${systemPrompt}\n\nAnalyze this scan data:\n${payload}`;
    
    const result = await chatSession.sendMessage(prompt);
    const responseText = result.response.text();
    
    const parsed = JSON.parse(stripJsonFences(responseText));

    if (!parsed.summary || !parsed.findings || !parsed.attack_surface) {
      throw new Error('Missing required JSON fields');
    }

    return parsed;
  } catch (error) {
    console.error('[analyzeVulnerabilities] Gemini Error:', error?.message || error);
    const fallback = buildFallbackAnalysis(scanInputData);
    fallback.summary.key_message = `AI analysis error: ${error?.message || 'Unknown error'}. Fallback data provided.`;
    return fallback;
  }
}

// ---------------------------------------------------------------------------
// Legacy Text Report
// ---------------------------------------------------------------------------

export async function aiReport(summaryText, language = 'english') {
  const normalizedLanguage = normalizeLanguage(language);
  
  const prompt = `You are a Cyber Security Analyst. Analyze scan results and explain them professionally to a website owner.
RULES:
1. Start with security posture. If results show only standard ports (80/443), report as "NOMINAL" or "SECURE".
2. Explain each issue. State that standard web ports are expected/safe.
3. Mention CVEs if provided. If none, state no exploitable entry points were detected.
4. Acknowledge Cloudflare protection if present.
5. Provide steps. If safe, suggest regular updates.
6. LANGUAGE: ${normalizedLanguage}
IMPORTANT: Do not exaggerate risks. Base analysis ONLY on provided data.

Raw scan data to analyze:
${summaryText}`;

  try {
    const result = await model.generateContent({
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.3 },
    });
    return result.response.text();
  } catch (error) {
    console.error('[aiReport] Gemini Error:', error?.message || error);
    return `ERROR: Gemini AI analysis failed. Details: ${error?.message}\n\nRaw scan data:\n\n${summaryText}`;
  }
}

// ---------------------------------------------------------------------------
// PoC Explanation
// ---------------------------------------------------------------------------

export async function generatePoCExplanation(vulnTitle) {
  const prompt = `You are an ethical hacking assistant. Explain the vulnerability "${vulnTitle}" to a beginner.
Return ONLY a valid JSON object with these exact keys:
- "what": What happened? (1 sentence, simple)
- "impact": Business impact? (1 sentence, simple)
- "danger": Why dangerous? (1 sentence, simple)
- "poc_result": Safe PoC success message.`;

  try {
    const result = await model.generateContent({
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: { 
        temperature: 0.3,
        responseMimeType: "application/json" 
      },
    });
    
    return JSON.parse(stripJsonFences(result.response.text()));
  } catch (error) {
    console.error('[generatePoCExplanation] Gemini Error:', error?.message || error);
    return {
      what: `The system verified a security flaw: "${vulnTitle}".`,
      impact: 'An attacker could gain unauthorized access or extract sensitive data.',
      danger: 'This vulnerability lets external actors interact with the system unexpectedly.',
      poc_result: 'Safe PoC executed successfully (no data was harmed).',
    };
  }
}
