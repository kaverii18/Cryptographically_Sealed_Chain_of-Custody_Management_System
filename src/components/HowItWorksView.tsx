/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  Shield,
  Layers,
  Lock,
  Eye,
  Stamp,
  CheckCheck,
  GitCommit,
  FileText,
  Bot,
  ArrowRight,
  Cpu,
  Fingerprint,
  Sparkles,
  HelpCircle,
  Database,
  Key,
} from 'lucide-react';

export const HowItWorksView: React.FC = () => {
  const [activeStage, setActiveStage] = useState<number>(0);

  const STAGES = [
    {
      id: 0,
      title: '1. Evidence Ingestion & Hashing',
      subtitle: 'NIST FIPS 180-4 SHA-256',
      icon: Cpu,
      color: 'text-cyan-400 bg-cyan-950/70 border-cyan-800',
      badge: 'FIPS 180-4 Compliant',
      summary:
        'Upon intake, the raw evidence specimen is streamed byte-for-byte through the browser’s native Web Crypto API. A 256-bit cryptographic digest is computed instantly.',
      details: [
        'Deterministic mathematical mapping: identical file always yields identical 64-character hex digest.',
        'Avalanche Effect: Modifying even a single bit in the file flips on average 50% of the output bits, making stealth manipulation impossible.',
        'Intake timestamp, collector badge number, and hardware details are recorded alongside the hash.',
      ],
      sample: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    },
    {
      id: 1,
      title: '2. Hash-Linked Custody Ledger',
      subtitle: 'ANSI X9.62 ECDSA P-256 Digital Signatures',
      icon: Lock,
      color: 'text-emerald-400 bg-emerald-950/70 border-emerald-800',
      badge: 'Tamper-Evident Chain',
      summary:
        'Every custody event (Collection, Transfer, Analysis, Storage, Release) forms an immutable cryptographic block containing the previous block’s hash and an ECDSA signature.',
      details: [
        'Backward Hash Linking: Each block records previousHash = SHA256(Block[N-1]). Altering block N breaks block N+1, N+2, through the head of the chain.',
        'Non-Repudiation: Every block is digitally signed using the officer’s private ECDSA key on the NIST P-256 elliptic curve.',
        'Instant Tamper Detection: The "Verify Chain" engine re-computes every hash and validates every signature in milliseconds.',
      ],
      sample: 'Previous Hash: 0000000000... ➔ Block Hash: 7a3f89d1c0... ➔ ECDSA Sig: 3045022100...',
    },
    {
      id: 2,
      title: '3. Fragile LSB Steganography',
      subtitle: 'AES-256-GCM Authenticated Encryption',
      icon: Eye,
      color: 'text-purple-400 bg-purple-950/70 border-purple-800',
      badge: 'Brittle Tamper Sensor',
      summary:
        'An encrypted payload containing case metadata and the current ledger head is embedded into the Least Significant Bits of the image pixels.',
      details: [
        'Passphrase Key Derivation: PBKDF2 with 100,000 iterations of SHA-256 and a random cryptographic salt.',
        'Extreme Fragility: Any spatial edit, crop, clone-patch, or lossy re-compression destroys the LSB bits, instantly failing the AES-GCM authentication tag.',
        'Visual Invisibility: Modifying the 8th bit alters color intensity by at most 1/256th (0.39%), imperceptible to the human eye (PSNR > 52 dB).',
      ],
      sample: 'Pixel R: 184 (10111000) ➔ Bit flipped to (10111001) = 185. Difference: Invisible.',
    },
    {
      id: 3,
      title: '4. Robust 2D-DCT Watermarking',
      subtitle: 'Frequency Domain Mid-Band Modulation',
      icon: Stamp,
      color: 'text-amber-400 bg-amber-950/70 border-amber-800',
      badge: 'Compression Survivor',
      summary:
        'While LSB steganography is intentionally fragile to detect tampering, DCT watermarking is intentionally robust to survive transmission and JPEG re-encoding.',
      details: [
        'YCbCr Separation: Watermarking operates strictly on the Y (luminance) channel where the human eye is least sensitive to subtle frequency shifts.',
        '8x8 Block 2D-DCT: Modifies mid-frequency coefficient pairs (4,3) and (3,4). High frequencies are discarded by JPEG; low frequencies cause visible artifacts.',
        'Majority Voting Redundancy: The 64-bit watermark ID is repeated hundreds of times across macroblocks, surviving heavy attacks.',
      ],
      sample: 'DCT Coeff (4,3) - (3,4) > +α encodes bit "1"; < -α encodes bit "0".',
    },
    {
      id: 4,
      title: '5. Automated 5-Check Verification & Heatmap',
      subtitle: 'Multi-Factor Forensic Decision Engine',
      icon: CheckCheck,
      color: 'text-cyan-400 bg-cyan-950/70 border-cyan-800',
      badge: 'Rule-Based Engine',
      summary:
        'A comprehensive 5-factor audit evaluates File Hash, Hidden Seal, Digital Signature, Ledger Chain, and Robust Watermark to issue an objective verdict.',
      details: [
        'Check 1: File Hash (100% byte integrity check).',
        'Check 2: Fragile Seal (AES-GCM decryption & payload integrity).',
        'Check 3: ECDSA Signature (Cryptographic origin validation).',
        'Check 4: Ledger Continuity (Backward hash pointer audit).',
        'Check 5: 2D-DCT Watermark (Bit-match survival score).',
        'Tamper Heatmap: 16x16 macroblock SSIM luminance variance maps highlight exact altered coordinates.',
      ],
      sample: 'Verdict: AUTHENTIC (All 5 PASS) | TAMPERED (Seal/Hash FAIL) | INCONCLUSIVE (Watermark PASS, Seal FAIL)',
    },
    {
      id: 5,
      title: '6. Merkle Case Seal & Selective Proofs',
      subtitle: 'RFC 6962 Binary Tree Inclusion Proofs',
      icon: GitCommit,
      color: 'text-emerald-400 bg-emerald-950/70 border-emerald-800',
      badge: 'Log₂(N) Privacy Proof',
      summary:
        'Binds hundreds of case evidence specimens (photos, RAM dumps, PCAP files, CCTV) into a single signed 32-byte Merkle root.',
      details: [
        'Hierarchical Hash Tree: Leaves are evidence hashes; parents are SHA256(Left + Right) recursively combined to the Merkle root.',
        'Privacy-Preserving Proofs: Present a single evidence item in court with proof of inclusion in the sealed case without disclosing sibling files.',
        'Cryptographic Case Seal: The examiner signs the Merkle root with ECDSA P-256 and commits a CASE_SEALED block to the ledger.',
      ],
      sample: 'Merkle Root = SHA256(Parent_L1_0 + Parent_L1_1) ➔ Proof = [Sibling_1, Sibling_2]',
    },
    {
      id: 6,
      title: '7. Self-Sealing PDF Reports & AI Auditor',
      subtitle: 'jsPDF + QR Integrity + Gemini 3.8 Flash',
      icon: FileText,
      color: 'text-purple-400 bg-purple-950/70 border-purple-800',
      badge: 'Courtroom Admissible',
      summary:
        'Generates standardized forensic PDF reports embedded with tamper heatmaps, chain of custody logs, self-integrity hashes, and grounded AI briefs.',
      details: [
        'Report Self-Integrity: The report content itself is hashed with SHA-256 and signed with the examiner’s ECDSA key.',
        'Verification QR: Scanning the QR code validates the report against the active case ledger.',
        'AI Forensic Auditor: Powered by Gemini 3.8 Flash in English or Marathi; operates strictly over non-sensitive structured data with zero raw image exposure.',
      ],
      sample: 'Formal Signature Blocks + Cryptographic QR + "AI Explanation (Non-Verdict Notice)"',
    },
  ];

  const current = STAGES[activeStage] || STAGES[0];
  const IconComp = current.icon;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Title */}
      <div className="space-y-2 border-b border-slate-800 pb-6">
        <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs font-semibold uppercase tracking-wider">
          <HelpCircle className="w-4 h-4" />
          <span>System Architecture & Technical Manual</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-slate-100 font-mono">
          How SealChain Secures Digital Evidence
        </h1>
        <p className="text-sm text-slate-400 max-w-3xl leading-relaxed">
          Digital forensic evidence must withstand rigorous legal challenges under Federal Rules of Evidence 901 and 902. SealChain employs a multi-layered defense-in-depth architecture combining symmetric encryption, asymmetric signatures, frequency watermarking, and hash trees.
        </p>
      </div>

      {/* Visual Pipeline Bar */}
      <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 shadow-xl overflow-x-auto no-scrollbar">
        <div className="flex items-center justify-between min-w-[700px] gap-2">
          {STAGES.map((s, idx) => {
            const SIcon = s.icon;
            const isActive = activeStage === idx;

            return (
              <React.Fragment key={s.id}>
                <button
                  onClick={() => setActiveStage(idx)}
                  className={`flex-1 p-3 rounded-lg border text-left transition-all font-mono text-xs cursor-pointer ${
                    isActive
                      ? 'bg-cyan-950/80 border-cyan-400 text-cyan-200 shadow-lg shadow-cyan-950/50'
                      : 'bg-slate-900 border-slate-800 hover:border-slate-700 text-slate-400'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <SIcon className="w-4 h-4 text-cyan-400" />
                    <span className="font-bold text-[11px] truncate">{s.subtitle}</span>
                  </div>
                  <div className="text-[10px] text-slate-400 truncate">{s.title}</div>
                </button>

                {idx < STAGES.length - 1 && (
                  <ArrowRight className="w-4 h-4 text-slate-600 shrink-0" />
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Deep-Dive Active Stage Card */}
      <div className="p-8 rounded-2xl bg-slate-950 border border-slate-800 shadow-2xl space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
          <div className="flex items-center gap-4">
            <div className={`p-3.5 rounded-xl border ${current.color}`}>
              <IconComp className="w-7 h-7" />
            </div>
            <div>
              <div className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider">
                Stage {activeStage + 1} of {STAGES.length}
              </div>
              <h2 className="text-xl font-bold font-mono text-slate-100">{current.title}</h2>
              <div className="text-xs font-mono text-slate-400">{current.subtitle}</div>
            </div>
          </div>

          <span className="px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-xs font-mono text-cyan-300 font-semibold self-start sm:self-auto">
            {current.badge}
          </span>
        </div>

        {/* Summary */}
        <p className="text-sm font-mono text-slate-200 leading-relaxed bg-slate-900/60 p-4 rounded-xl border border-slate-800/80">
          {current.summary}
        </p>

        {/* Detailed Points */}
        <div className="space-y-3 font-mono text-xs">
          <h3 className="text-slate-300 font-bold uppercase tracking-wider text-[11px]">
            Key Cryptographic Principles:
          </h3>
          <ul className="space-y-2.5">
            {current.details.map((point, idx) => (
              <li key={idx} className="flex items-start gap-2.5 text-slate-300 leading-relaxed">
                <span className="text-cyan-400 shrink-0 mt-0.5">▸</span>
                <span>{point}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Sample Payload / Formula */}
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
          <div className="text-[10px] font-mono uppercase text-slate-400">
            Technical Specification & Data Encoding:
          </div>
          <div className="text-xs font-mono text-cyan-300 break-all bg-black/40 p-2.5 rounded border border-white/5">
            {current.sample}
          </div>
        </div>

        {/* Navigation buttons between stages */}
        <div className="flex items-center justify-between pt-4 border-t border-slate-800">
          <button
            onClick={() => setActiveStage((prev) => Math.max(0, prev - 1))}
            disabled={activeStage === 0}
            className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 disabled:opacity-40 text-xs font-mono text-slate-300 transition-colors"
          >
            ← Previous Stage
          </button>

          <span className="text-xs font-mono text-slate-500">
            {activeStage + 1} / {STAGES.length}
          </span>

          <button
            onClick={() => setActiveStage((prev) => Math.min(STAGES.length - 1, prev + 1))}
            disabled={activeStage === STAGES.length - 1}
            className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 disabled:opacity-40 text-xs font-mono text-slate-300 transition-colors"
          >
            Next Stage →
          </button>
        </div>
      </div>
    </div>
  );
};
