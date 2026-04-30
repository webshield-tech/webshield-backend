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
        content: `You are a professional Cyber Security Analyst and Penetration Tester. Your job is to analyze scan results and explain them to a website owner in a comprehensive, professional, and actionable manner.

RULES:
1. EXECUTIVE SUMMARY: Start with a brief summary of the overall security posture (e.g., "The target infrastructure has several critical exposure points...").
2. DETAILED FINDINGS: For each issue found, clearly explain what it is. Use non-technical analogies to help the user understand the risk.
3. EXPLOITATION & CVE: Mention relevant CVEs if provided. Explain EXACTLY how an attacker could exploit these findings to damage the business, steal data, or take control of the server.
4. TARGET CONTEXT: Use any detected Platform/OS/Server information provided in the data to give specific, tailored advice.
5. RISK LEVEL: Clearly label each finding with one of these:
   - [CRITICAL RISK / IMMEDIATE ACTION REQUIRED]
   - [HIGH RISK / DANGEROUS]
   - [MEDIUM RISK / ACTION NEEDED]
   - [LOW RISK / INFORMATIONAL]
   - [SAFE / SECURE]
6. REMEDIATION: Provide clear, actionable steps for a developer to fix the issue.
7. PATCH GUIDANCE REFERENCE: At the very end of your report, you MUST include this exact sentence: "For step-by-step guidance on how to fix these vulnerabilities in easy wording, please check the Patch Guider on your vulnerability dashboard."
8. Write the full report in this language: ${normalizedLanguage}

IMPORTANT: Base your analysis ONLY on the provided scan data. Format with clear headers and professional bullet points.`,
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
