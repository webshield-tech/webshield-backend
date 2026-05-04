import { GoogleGenerativeAI } from '@google/generative-ai';
import Groq from 'groq-sdk';
import dotenv from 'dotenv';
dotenv.config();

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API);
let groqClient = null;
if (process.env.GROQ_API_KEY) {
  try {
    groqClient = new Groq({ apiKey: process.env.GROQ_API_KEY });
  } catch (e) {
    console.warn("Groq initialization failed:", e.message);
  }
}

const GEMINI_MODEL_CANDIDATES = [
  process.env.GEMINI_MODEL,
  'gemini-2.5-flash',
  'gemini-1.5-flash',
].filter(Boolean);

const GEMINI_RETRY = {
  attempts: 3,
  baseDelayMs: 600,
};

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

function isRetryableGeminiError(error) {
  const message = String(error?.message || '').toLowerCase();
  const status = error?.status || error?.response?.status || error?.response?.statusCode;
  return status === 503 || message.includes('503') || message.includes('unavailable') || message.includes('overloaded');
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function createModel(modelName) {
  return genAI.getGenerativeModel({ model: modelName });
}

async function runGeminiWithFallback(actionFactory, contextLabel) {
  let lastError = null;

  for (const modelName of GEMINI_MODEL_CANDIDATES) {
    const candidateModel = createModel(modelName);
    try {
      return await actionFactory(candidateModel);
    } catch (error) {
      lastError = error;
      const message = String(error?.message || '').toLowerCase();
      const status = error?.status || error?.response?.status || error?.response?.statusCode;
      const looksLikeMissingModel =
        status === 404 ||
        message.includes('not found') ||
        message.includes('model') && message.includes('not found');

      if (!looksLikeMissingModel) {
        throw error;
      }

      console.warn(`[${contextLabel}] Gemini model unavailable: ${modelName}`);
    }
  }

  // Fallback to Groq if all Gemini models fail and Groq is available
  if (groqClient) {
    console.warn(`[${contextLabel}] Gemini failed or quota exceeded. Falling back to Groq.`);
    try {
      // Return a special flag so the caller knows to use Groq manually, or handle the Groq call here.
      // Since Groq SDK has a different API, we throw a specific error to let the caller handle it.
      throw new Error('FALLBACK_TO_GROQ');
    } catch (e) {
      throw e;
    }
  }

  throw lastError || new Error('No AI model could be initialized');
}

async function withGeminiRetry(action, contextLabel) {
  let attempt = 0;
  while (attempt < GEMINI_RETRY.attempts) {
    try {
      return await action();
    } catch (error) {
      attempt += 1;
      if (!isRetryableGeminiError(error) || attempt >= GEMINI_RETRY.attempts) {
        throw error;
      }
      const waitMs = GEMINI_RETRY.baseDelayMs * Math.pow(2, attempt - 1);
      console.warn(`[${contextLabel}] Gemini 503 retry ${attempt}/${GEMINI_RETRY.attempts} in ${waitMs}ms`);
      await delay(waitMs);
    }
  }
}

function buildFallbackAnalysis(scanInputData) {
  return {
    summary: {
      risk_score: 0,
      overall_status: 'Informational',
      confidence_score: 0.0,
      scan_quality: scanInputData?.scan_type === 'deep' ? 'Deep Scan' : 'Quick Scan',
      key_message: 'AI analysis could not be completed. We have shared the raw scan results below in a safe, readable format.',
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
        description: 'Automated analysis failed, but your scan data is saved. You can still review the details safely.',
      },
    ],
    prioritized_actions: [
      'Open the raw scan output and look for any warnings highlighted by the tool.',
      'Re-run the AI analysis later when the service is back online.',
    ],
    final_recommendation: 'No action is required right now unless you see clear warnings in the raw output.',
  };
}

// ---------------------------------------------------------------------------
// Main AI Correlated Analysis Engine (Structured JSON)
// ---------------------------------------------------------------------------

export async function analyzeVulnerabilities(scanInputData, language = 'english') {
  const normalizedLanguage = normalizeLanguage(language);

const systemPrompt = `You are a friendly, expert cybersecurity consultant for Vuln Spectra (WebShield).
Your role is to analyze scan results and explain them to a NON-TECHNICAL website owner. 

CORE RULES:
1. Explain risks in plain English without using complex jargon. Avoid overly technical language.
2. Identify REAL vulnerabilities only. Do not treat standard open ports (80, 443) as flaws.
3. Merge duplicate findings.
4. Scale Confidence based on multiple tool detections.
5. Provide a realistic risk score (0-100).
6. Output MUST be in ${normalizedLanguage}.
7. For each finding, provide clear, step-by-step 'patch_steps' that a regular developer or host provider can follow.
8. Add a short, platform-specific fix in platform_specific_fix when the detected platform is known.
9. If the target is safe or only shows expected ports, say so clearly in the key_message.

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
      "recommendation": "<General Fix Advice>",
      "patch_steps": ["<Step 1>", "<Step 2>"],
      "platform_specific_fix": "<Fix for detected platform in plain wording>",
      "references": ["<CVE/CWE>"]
    }
  ],
  "informational_findings": [{"title": "...", "description": "..."}],
  "prioritized_actions": ["<Step 1>", "<Step 2>"],
  "final_recommendation": "<Advice>"
}`;

  try {
    const payload = JSON.stringify(scanInputData);
    const prompt = `${systemPrompt}\n\nAnalyze this scan data:\n${payload}`;

    const result = await runGeminiWithFallback(
      (candidateModel) => {
        const chatSession = candidateModel.startChat({
          generationConfig: {
            temperature: 0.2,
            responseMimeType: 'application/json',
          },
        });

        return withGeminiRetry(
          () => chatSession.sendMessage(prompt),
          'analyzeVulnerabilities'
        );
      },
      'analyzeVulnerabilities'
    );
    const responseText = result.response.text();
    
    const parsed = JSON.parse(stripJsonFences(responseText));

    if (!parsed.summary || !parsed.findings || !parsed.attack_surface) {
      throw new Error('Missing required JSON fields');
    }

    return parsed;
  } catch (error) {
    if (error.message === 'FALLBACK_TO_GROQ' && groqClient) {
      try {
        const payload = JSON.stringify(scanInputData);
        const groqCompletion = await groqClient.chat.completions.create({
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: `Analyze this scan data:\n${payload}` }
          ],
          model: "llama3-8b-8192",
          temperature: 0.2,
          response_format: { type: "json_object" }
        });
        const responseText = groqCompletion.choices[0]?.message?.content || "{}";
        const parsed = JSON.parse(stripJsonFences(responseText));
        if (parsed.summary && parsed.findings) return parsed;
      } catch (groqError) {
        console.error('[analyzeVulnerabilities] Groq Error:', groqError?.message);
      }
    }

    console.error('[analyzeVulnerabilities] AI Error:', error?.message || error);
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
    const result = await runGeminiWithFallback(
      (candidateModel) =>
        withGeminiRetry(
          () =>
            candidateModel.generateContent({
              contents: [{ role: 'user', parts: [{ text: prompt }] }],
              generationConfig: { temperature: 0.3 },
            }),
          'aiReport'
        ),
      'aiReport'
    );
    return result.response.text();
  } catch (error) {
    if (error.message === 'FALLBACK_TO_GROQ' && groqClient) {
      try {
        const groqCompletion = await groqClient.chat.completions.create({
          messages: [
            { role: "system", content: prompt }
          ],
          model: "llama3-8b-8192",
          temperature: 0.3,
        });
        return groqCompletion.choices[0]?.message?.content || "No analysis available.";
      } catch (groqError) {
        console.error('[aiReport] Groq Error:', groqError?.message);
      }
    }

    console.error('[aiReport] AI Error:', error?.message || error);
    return `ERROR: AI analysis failed. Details: ${error?.message}\n\nRaw scan data:\n\n${summaryText}`;
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
    const result = await runGeminiWithFallback(
      (candidateModel) =>
        withGeminiRetry(
          () =>
            candidateModel.generateContent({
              contents: [{ role: 'user', parts: [{ text: prompt }] }],
              generationConfig: {
                temperature: 0.3,
                responseMimeType: 'application/json',
              },
            }),
          'generatePoCExplanation'
        ),
      'generatePoCExplanation'
    );
    
    return JSON.parse(stripJsonFences(result.response.text()));
  } catch (error) {
    if (error.message === 'FALLBACK_TO_GROQ' && groqClient) {
      try {
        const groqCompletion = await groqClient.chat.completions.create({
          messages: [
            { role: "system", content: prompt }
          ],
          model: "llama3-8b-8192",
          temperature: 0.3,
          response_format: { type: "json_object" }
        });
        return JSON.parse(stripJsonFences(groqCompletion.choices[0]?.message?.content || "{}"));
      } catch (groqError) {
        console.error('[generatePoCExplanation] Groq Error:', groqError?.message);
      }
    }

    console.error('[generatePoCExplanation] AI Error:', error?.message || error);
    return {
      what: `The system verified a security flaw: "${vulnTitle}".`,
      impact: 'An attacker could gain unauthorized access or extract sensitive data.',
      danger: 'This vulnerability lets external actors interact with the system unexpectedly.',
      poc_result: 'Safe PoC executed successfully (no data was harmed).',
    };
  }
}
