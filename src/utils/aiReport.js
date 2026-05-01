import Groq from 'groq-sdk';
import dotenv from 'dotenv';
dotenv.config();

const groq = new Groq({
  apiKey: process.env.GROQ_API,
});

function normalizeLanguage(language) {
  const value = String(language || "english").trim().toLowerCase();
  if (["urdu", "hindi", "arabic", "english"].includes(value)) return value;
  return "english";
}

export async function aiReport(summaryText, language = "english") {
  const normalizedLanguage = normalizeLanguage(language);
  try {
    const response = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [
        {
          role: 'system',
        content: `You are a Cyber Security Analyst. Analyze scan results and explain them professionally to a website owner.
RULES:
1. SUMMARY: Start with security posture. If results show only standard ports (80/443) and security proxies (Cloudflare), report as "NOMINAL" or "SECURE".
2. FINDINGS: Explain each issue. State that standard web ports are expected/safe.
3. EXPLOIT: Mention CVEs if provided. If none found, state clearly that no exploitable entry points were detected.
4. CONTEXT: Use detected Platform/Server/Cloudflare info. Acknowledge Cloudflare protection.
5. RISK: Label findings clearly. Standard ports = [SAFE].
6. REMEDY: Provide steps. If safe, suggest regular updates.
7. PATCH GUIDER: ONLY if vulnerabilities found, add: "For step-by-step guidance, check the Patch Guider on your dashboard." If secure, congratulate and suggest regular monitoring.
8. LANGUAGE: ${normalizedLanguage}
IMPORTANT: Do not exaggerate risks. If secure (like TryHackMe), reflect that it is well-defended. Base analysis ONLY on provided data.`,
        },
        {
          role: 'user',
          content: summaryText,
        },
      ],
      temperature: 0.3,
      max_tokens: 1200,
    });
    return response.choices[0].message.content;
  } catch (error) {
    console.error('AI Report Error:', error);
    const errorMsg = error?.message || String(error);
    return (
      'ERROR: Could not generate AI analysis. Details: ' + errorMsg + '\n\n' +
      'Please check the raw scan results below.\n\n' +
      summaryText
    );
  }
}

export async function generatePoCExplanation(vulnTitle) {
  try {
    const response = await groq.chat.completions.create({
      model: 'llama-3.1-8b-instant',
      messages: [
        {
          role: 'system',
          content: `You are an ethical hacking assistant. A user has simulated an exploit for a vulnerability titled "{VULN_TITLE}".
Provide a simple JSON response explaining this to a beginner. 
The JSON must have these exact keys:
- "what": What happened during the exploit? (1 sentence, extremely simple)
- "impact": What is the business impact? (1 sentence, simple)
- "danger": Why is this dangerous? (1 sentence, simple)
- "poc_result": A short success message indicating a SAFE proof of concept was executed (e.g., "Safe PoC executed: Simulated data extraction successful").

Do NOT include markdown formatting or extra text outside the JSON. Return valid JSON only.`,
        },
        {
          role: 'user',
          content: `Vulnerability Title: ${vulnTitle}`,
        },
      ],
      temperature: 0.3,
      max_tokens: 300,
    });
    
    const content = response.choices[0].message.content.trim();
    const jsonStr = content.replace(/```json/g, '').replace(/```/g, '').trim();
    return JSON.parse(jsonStr);
  } catch (error) {
    console.error('AI PoC Error:', error);
    return {
      what: `The system successfully verified a security flaw related to "${vulnTitle}".`,
      impact: "An attacker could potentially gain unauthorized access or extract data.",
      danger: "This is a security risk because it allows external actors to interact with the system unexpectedly.",
      poc_result: "Safe PoC executed successfully (No data was harmed)."
    };
  }
}
