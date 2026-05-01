import { GoogleGenerativeAI } from '@google/generative-ai';
import dotenv from 'dotenv';
dotenv.config();

async function test() {
  const genAI = new GoogleGenerativeAI(process.env.GEMINI_API);
  try {
    const model = genAI.getGenerativeModel({ model: 'gemini-flash-latest' });
    const result = await model.generateContent('Hi');
    console.log("gemini-flash-latest worked:", result.response.text());
  } catch (e) {
    console.log("gemini-flash-latest failed:", e.message);
  }
}
test();
