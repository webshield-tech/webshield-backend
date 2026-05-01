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
        content: `You are a professional Cyber Security Analyst and Penetration Tester. Your job is to analyze scan results and explain them to a website owner in a comprehensive, professional, and actionable manner.

RULES:
1. EXECUTIVE SUMMARY: Start with a brief summary of the overall security posture. If the results show only standard ports (80/443) and security proxies (like Cloudflare), report the status as "NOMINAL" or "SECURE".
2. DETAILED FINDINGS: For each issue found, clearly explain what it is. If it's a standard web port, explain that it is expected for web traffic and not a risk.
3. EXPLOITATION & CVE: Mention relevant CVEs if provided. If NO vulnerabilities are found, state clearly that no exploitable entry points were detected during this specific scan.
4. TARGET CONTEXT: Use detected Platform/OS/Server/Cloudflare info. Acknowledge that tools like Cloudflare increase security.
5. RISK LEVEL: Clearly label each finding. If it's just an open standard port, use [SAFE / SECURE] or [LOW RISK / INFORMATIONAL].
6. REMEDIATION: Provide clear steps. If it's safe, suggest continuing to keep software updated.
7. PATCH GUIDANCE REFERENCE: ONLY if vulnerabilities or risks were found, you MUST include this exact sentence at the end: "For step-by-step guidance on how to fix these vulnerabilities in easy wording, please check the Patch Guider on your vulnerability dashboard." If the site is fully secure/nominal, do NOT include this sentence. Instead, congratulate the user and suggest regular monitoring.
8. Write the full report in this language: ${normalizedLanguage}

IMPORTANT: Do NOT exaggerate risks. If a website is secure (like TryHackMe or Cloudflare-protected sites), your report must reflect that it is well-defended. Base your analysis ONLY on the provided scan data.`,
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
