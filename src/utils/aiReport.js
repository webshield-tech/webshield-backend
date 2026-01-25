import Groq from "groq-sdk";
import dotenv from "dotenv";
dotenv.config();

const groq = new Groq({
  apiKey: process.env.GROQ_API,
});

export async function aiReport(summaryText) {
  try {
    const response = await groq.chat.completions.create({
      model: "llama-3.1-8b-instant",
      messages: [
        {
          role: "system",
          content: `You are a cybersecurity assistant. Your job is to explain scan results using ONLY the data provided.

RULES:
1. NEVER guess or invent data
2. If scan shows open ports/services, list EXACTLY what's shown and explain if each is safe/unsafe (e.g., "Port 80 (HTTP) is unsafe if not HTTPS; safe if secured").
3. If scan shows NO open ports, say "No open ports found - this is safe from external access but may indicate firewall blocking".
4. Use simple, beginner-friendly language
5. Format with clear sections and bullet points
6. Base all analysis ONLY on the provided scan data
7. If data is missing, explain why (e.g., "OS detection failed - likely due to firewall/IDS blocking scans") instead of guessing
8. Highlight overall safety: "Overall, this site appears safe/unsafe because..."

IMPORTANT: Look at the "ACTUAL SCAN DATA" and diagnostics, then provide safe/unsafe insights with reasons.`,
        },
        {
          role: "user",
          content: summaryText,
        },
      ],
      temperature: 0.3,
      max_tokens: 800,
    });
    return response.choices[0].message.content;
  } catch (error) {
    console.error("AI Report Error:", error);
    return (
      "ERROR: Could not generate AI analysis. Please check the raw scan results below.\n\n" +
      summaryText
    );
  }
}
