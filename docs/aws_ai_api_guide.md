# AWS AI / Groq API Integration Guide for WebShield (Vuln Spectra)

Vuln Spectra utilizes AI for intelligent vulnerability reporting and automated Proof of Concept (PoC) explanations. This guide details how to configure the backend to use the Groq API (or an AWS AI equivalent).

## Overview
The AI integration converts raw scanning engine outputs (from Nmap, Nikto, SQLMap, SSLScan) into comprehensive, human-readable security reports. It also provides beginner-friendly, contextual explanations when a vulnerability is successfully exploited during a PoC simulation.

## Prerequisites
- Node.js installed
- WebShield Backend configured (`webshield-backend`)
- API key for Groq (or your chosen AI provider)

## 1. Setting the API Key
In the root directory of your backend (`webshield-backend`), create or open the `.env` file.

Add the following variable:
```env
GROQ_API=your_groq_api_key_here
```
*(Ensure you replace `your_groq_api_key_here` with your actual key from the Groq console).*

## 2. API Usage & Integration points

### a) Vulnerability Report Generation
Located in `src/utils/aiReport.js` and `src/controllers/aiReport-controller.js`.
- The engine sanitizes and compresses raw logs to prevent exceeding context window limits.
- The `aiReport` function calls the Groq API utilizing the `llama3-70b-8192` or `llama3-8b-8192` models.
- It asks the AI to format the report based on the requested language (English, Urdu, Hindi, Arabic).

### b) PoC Simulation Explanations
Located in `src/utils/aiReport.js` and `src/controllers/exploit-controller.js`.
- When a user triggers an auto-exploit, the `generatePoCExplanation(vulnTitle)` function is called.
- The Groq API generates a JSON response detailing:
  - **What happened:** A simple explanation of the exploit.
  - **Impact:** The potential damage.
  - **Danger:** Why this vulnerability is critical.
  - **PoC Result:** A simulated outcome of the attack.
- The response must be structured as valid JSON, which is then parsed and sent to the frontend `ScanResult.tsx` to display in an interactive modal.

## 3. Rate Limits & Performance
- **Timeout**: Deep scans with extensive logs can take time. Ensure the frontend timeout and backend processing can handle up to a 60-second delay for AI generation.
- **Token Limits**: Nmap and Nikto raw outputs can easily exceed token limits. The backend specifically parses `openPorts`, `serviceVersions`, and `CVEs` from Nmap to compress the context before sending it to the Groq API.
- **Model Choice**: The 70b model provides better contextual nuance for security reporting, while the 8b model is faster for simple PoC explanations.

## 4. Troubleshooting
- **API Key Error:** Ensure `process.env.GROQ_API` is loaded properly. You may need to restart the backend node process if the `.env` file was updated.
- **JSON Parsing Errors:** In `generatePoCExplanation`, the Groq response is parsed as JSON. If the model outputs conversational text before the JSON block, parsing will fail. The prompt specifically instructs the model to return *only* JSON.

## 5. Transitioning to AWS AI Services (Optional)
If migrating from Groq to AWS Bedrock (e.g., using Claude 3 or Llama 3 on AWS):
1. Install the `@aws-sdk/client-bedrock-runtime` package.
2. Update the `aiReport.js` to initialize the `BedrockRuntimeClient`.
3. Map the system prompts to the required AWS payload structure (which differs from OpenAI/Groq standard REST shapes).
4. Provide `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in the `.env` file with appropriate IAM roles.
