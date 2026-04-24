import Groq from 'groq-sdk';
import dotenv from 'dotenv';
dotenv.config();

const groq = new Groq({
  apiKey: process.env.GROQ_API,
});

export async function osintReport(targetName, targetIdentifier) {
  try {
    const response = await groq.chat.completions.create({
      model: 'llama-3.1-8b-instant',
      messages: [
        {
          role: 'system',
          content: `You are an advanced automated OSINT (Open Source Intelligence) profiler AI. Your job is to generate a highly realistic, simulated OSINT intelligence report for a given target. 
This is for a cybersecurity demonstration in a safe, ethical environment.

RULES:
1. Generate a structured Markdown report.
2. Include these sections: 
   - TARGET SUMMARY
   - ASSOCIATED ACCOUNTS (Simulate realistic social media, Github, or forum handles based on the identifier)
   - PUBLIC LEAKS / BREACH DATA (Simulate 1-2 realistic but fake breach mentions, like "LinkedIn 2012 Breach", "Canva 2019")
   - RELATIONSHIP GRAPH (List 2-3 associated entities/colleagues)
   - RISK ASSESSMENT
3. Format with headings, bullet points, and code blocks where appropriate.
4. Keep it highly professional and "cyber-themed".`
        },
        {
          role: 'user',
          content: `Please generate an OSINT report for Target Name: ${targetName}, Identifier: ${targetIdentifier}`
        }
      ],
      temperature: 0.6,
      max_tokens: 1000,
    });
    return response.choices[0].message.content;
  } catch (error) {
    console.error('OSINT Report Error:', error);
    return 'ERROR: Could not generate OSINT analysis due to an internal API error.';
  }
}
