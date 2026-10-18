/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express, { Request, Response } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';
import { createServer as createViteServer } from 'vite';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '10mb' }));

  // Initialize Google GenAI client if API key is present
  const apiKey = process.env.GEMINI_API_KEY;
  let ai: GoogleGenAI | null = null;
  if (apiKey && apiKey !== 'MY_GEMINI_API_KEY') {
    ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }

  // Health check endpoint
  app.get('/api/health', (req: Request, res: Response) => {
    res.json({
      status: 'ok',
      hasApiKey: !!ai,
      serverTime: new Date().toISOString(),
    });
  });

  // Forensic Explanation Endpoint
  app.post('/api/ai/explain', async (req: Request, res: Response) => {
    try {
      const { forensicData, language = 'en' } = req.body;

      if (!forensicData) {
        return res.status(400).json({ error: 'Missing forensic data payload', fallbackNeeded: true });
      }

      if (!ai) {
        return res.json({
          ok: false,
          fallbackNeeded: true,
          message: 'No GEMINI_API_KEY configured on server; use deterministic fallback.',
        });
      }

      const isMr = language === 'mr';
      const promptLang = isMr ? 'Marathi (मराठी)' : 'English';

      const systemInstruction = `You are an expert Senior Digital Forensics Auditor and Cryptographic Examiner assisting in criminal and judicial proceedings for the SealChain system.
CRITICAL RULES:
1. Base your explanation EXCLUSIVELY on the structured forensic results provided in the prompt. NEVER invent, hallucinate, or presume any facts not directly stated in the evidence data.
2. NEVER claim that you made the verdict. Emphasize that the verdict was determined mathematically by the deterministic 5-check forensic engine. Your role is strictly explanatory.
3. Structure your response into 3 clear sections:
   - What Was Found & Forensic Assessment (verdict, confidence score, summary)
   - Why Each Check Passed or Failed (detailed explanation of SHA-256 bit integrity, LSB fragile stego decryption, ECDSA P-256 signature, ledger backward hash continuity, and 2D-DCT watermark resilience)
   - Actionable Recommendations for the Investigating Officer (chain of custody review, subpoena advice, judicial admissibility)
4. Clearly state limits: AI assists in interpretation and pattern analysis; judicial admissibility relies on cryptographic proof and the court's discretion.
5. LANGUAGE: Respond strictly and entirely in ${promptLang}. ${
        isMr
          ? 'Use formal, clear Marathi while keeping recognized technical terms in brackets or standard Marathi forensic terms (उदा. हॅश, डिजिटल स्वाक्षरी, लेजर, वॉटरमार्क).'
          : 'Use formal, objective, court-admissible forensic phrasing.'
      }`;

      const userPrompt = `Here is the verified cryptographic forensic data for Evidence ID "${
        forensicData.evidenceId
      }" (Case: "${forensicData.caseId}"):

- Verdict: ${forensicData.verdict}
- Confidence Score: ${forensicData.confidencePercent}%
- Suspect Specimen SHA-256: ${forensicData.suspectImageSha256}
- 5 Independent Checks:
  1. File Hash Check: ${forensicData.checks?.fileHash?.status} - ${forensicData.checks?.fileHash?.reason}
  2. Hidden LSB Seal (AES-GCM): ${forensicData.checks?.hiddenSeal?.status} - ${forensicData.checks?.hiddenSeal?.reason}
  3. ECDSA P-256 Signature: ${forensicData.checks?.signature?.status} - ${forensicData.checks?.signature?.reason}
  4. Custody Ledger Integrity: ${forensicData.checks?.ledgerIntegrity?.status} - ${forensicData.checks?.ledgerIntegrity?.reason}
  5. Robust 2D-DCT Watermark: ${forensicData.checks?.robustWatermark?.status} - ${forensicData.checks?.robustWatermark?.reason}
- Identified Anomalous Regions: ${
        forensicData.suspiciousRegions?.length > 0
          ? JSON.stringify(forensicData.suspiciousRegions)
          : 'None detected (all blocks intact)'
      }
- Attack/Tampering Vector: ${forensicData.attackType || 'None recorded'}
- Custody Ledger Summary: ${forensicData.ledgerSummary?.totalBlocks || 0} blocks, chain unbroken: ${
        forensicData.ledgerSummary?.isChainValid ? 'YES' : 'NO'
      }

Please provide a comprehensive forensic analysis explaining these exact results in ${promptLang}.`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: userPrompt,
        config: {
          systemInstruction,
          temperature: 0.2, // Low temperature for high precision and groundedness
        },
      });

      const explanationText = response.text || '';
      return res.json({
        ok: true,
        explanation: explanationText,
        language,
        modelUsed: 'gemini-3.8-flash',
      });
    } catch (err: unknown) {
      console.error('Gemini API explain error:', err);
      const errorMessage = err instanceof Error ? err.message : String(err);
      return res.json({
        ok: false,
        fallbackNeeded: true,
        error: errorMessage,
      });
    }
  });

  // Forensic Chat Endpoint
  app.post('/api/ai/chat', async (req: Request, res: Response) => {
    try {
      const { messages, forensicData, language = 'en' } = req.body;

      if (!messages || !Array.isArray(messages)) {
        return res.status(400).json({ error: 'Messages array required', fallbackNeeded: true });
      }

      if (!ai) {
        return res.json({
          ok: false,
          fallbackNeeded: true,
          message: 'No GEMINI_API_KEY configured; use fallback.',
        });
      }

      const isMr = language === 'mr';
      const promptLang = isMr ? 'Marathi (मराठी)' : 'English';

      const systemInstruction = `You are the SealChain AI Forensic Assistant.
Answer questions from investigators, defense counsel, or judges about this specific forensic case.
Ground every statement strictly in the following case data:
Case: ${forensicData?.caseId || 'Unknown'}
Evidence: ${forensicData?.evidenceId || 'Unknown'}
Verdict: ${forensicData?.verdict || 'Unknown'} (${forensicData?.confidencePercent || 0}% confidence)
Checks: Hash=${forensicData?.checks?.fileHash?.status}, Seal=${forensicData?.checks?.hiddenSeal?.status}, Sig=${
        forensicData?.checks?.signature?.status
      }, Chain=${forensicData?.checks?.ledgerIntegrity?.status}, Watermark=${
        forensicData?.checks?.robustWatermark?.status
      }
Suspicious Regions: ${JSON.stringify(forensicData?.suspiciousRegions || [])}
Rules:
1. Do not invent any facts.
2. If asked something not in the data, state clearly that the evidence data does not contain that information.
3. Language: Respond strictly in ${promptLang}.`;

      const formattedContents = messages.map((m: { role: string; text: string }) => ({
        role: m.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: m.text }],
      }));

      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: formattedContents,
        config: {
          systemInstruction,
          temperature: 0.3,
        },
      });

      const replyText = response.text || '';
      return res.json({
        ok: true,
        reply: replyText,
      });
    } catch (err: unknown) {
      console.error('Gemini API chat error:', err);
      const errorMessage = err instanceof Error ? err.message : String(err);
      return res.json({
        ok: false,
        fallbackNeeded: true,
        error: errorMessage,
      });
    }
  });

  // Mount Vite middleware in development mode
  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  const PORT = Number(process.env.PORT) || 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SealChain Full-Stack Forensic Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Fatal server startup error:', err);
  process.exit(1);
});
