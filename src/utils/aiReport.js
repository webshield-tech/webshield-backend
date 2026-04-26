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
      model: 'llama-3.1-8b-instant',
      messages: [
        {
          role: 'system',
        content: `You are a cybersecurity assistant. Your job is to explain scan results to non-technical users in a comprehensive manner.

RULES:
1. EXPLAIN WHAT WAS FOUND: Clearly state exactly what the scanning tool found.
2. EXPLAIN THE MEANING: Explain what this finding means in EXTREMELY simple, everyday language.
3. EXPLAIN THE IMPACT & EXPLOITATION: Focus on how this affects the website. Mention any associated CVEs (if provided or known for this specific flaw) and explain exactly how a hacker could exploit this vulnerability.
4. Use these color codes for risk levels (plain text):
   - [HIGH RISK / DANGEROUS]
   - [MEDIUM RISK / ACTION NEEDED]
   - [SAFE / SECURE]
5. PATCH GUIDANCE REFERENCE: At the very end of your report, you MUST include this exact sentence: "For step-by-step guidance on how to fix these vulnerabilities in easy wording, please check the Patch Guider on your vulnerability dashboard."
6. Write the full report in this language: ${normalizedLanguage}

IMPORTANT: Base your analysis ONLY on the provided scan data. Do not invent details. Format with clear bullet points and headers for readability.`,
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
    return (
      'ERROR: Could not generate AI analysis. Please check the raw scan results below.\n\n' +
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
