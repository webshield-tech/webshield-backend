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
        content: `You are a cybersecurity assistant. Your job is to explain scan results using ONLY the data provided.

RULES:
1. NEVER guess or invent data. Base all analysis ONLY on the provided scan data.
2. Use EXTREMELY simple, non-technical, beginner-friendly language. Explain what the vulnerability is and why it is dangerous in real-world terms (e.g., "Attackers could steal user data").
3. You MUST color-code your findings using explicit text markers:
   - [🔴 RED / High Risk] for critical vulnerabilities like SQL Injection, XSS, open dangerous ports, or expired SSL.
   - [🟠 ORANGE / Medium Risk] for medium issues like information disclosure or outdated services.
   - [🟢 GREEN / Safe] for secure configurations and safe ports.
4. If CVEs are detected, list them clearly and explain what they mean in simple terms.
5. Provide a "Recommendations" section at the end with actionable steps.
6. If scan shows NO open ports or issues, clearly state it is [🟢 GREEN / Safe].
7. Write the full report in this language: ${normalizedLanguage}

IMPORTANT: Look at the "ACTUAL SCAN DATA" and format with clear sections, bullet points, and the required color codes.`,
        },
        {
          role: 'user',
          content: summaryText,
        },
      ],
      temperature: 0.3,
      max_tokens: 800,
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
