/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  Sparkles,
  ChevronRight,
  ChevronLeft,
  X,
  Play,
  CheckCircle2,
  Lock,
  Cpu,
  Eye,
  Stamp,
  CheckCheck,
  Bot,
  FileText,
  GitCommit,
} from 'lucide-react';
import { AppTab } from './Navbar';

export interface DemoStep {
  stepNumber: number;
  title: string;
  tab: AppTab;
  cueNote: string;
  actionLabel?: string;
  icon: React.ComponentType<{ className?: string }>;
}

export const DEMO_STEPS: DemoStep[] = [
  {
    stepNumber: 1,
    title: 'Evidence Intake & SHA-256 Digest',
    tab: 'intake',
    cueNote:
      'Demonstrate how evidence bytes stream through crypto.subtle.digest to compute an authentic FIPS 180-4 SHA-256 hash.',
    icon: Cpu,
  },
  {
    stepNumber: 2,
    title: 'Immutable Custody Ledger & ECDSA Signatures',
    tab: 'ledger',
    cueNote:
      'Show the vertical blockchain of custody blocks. Point out backward hash pointers and the "Verify Chain" button.',
    icon: Lock,
  },
  {
    stepNumber: 3,
    title: 'Fragile LSB Stego & 2D-DCT Robust Watermark',
    tab: 'steganography',
    cueNote:
      'Explain defense-in-depth: Brittle LSB seal detects single-bit tampering, while 2D-DCT watermark survives JPEG compression.',
    icon: Eye,
  },
  {
    stepNumber: 4,
    title: 'Simulate Tampering & 5-Check Detection',
    tab: 'verification',
    cueNote:
      'Click "Simulate Attack" (e.g. Clone-Paste or Pixel Patch) to see the 5-check engine isolate tampered coordinates on the heatmap.',
    icon: CheckCheck,
  },
  {
    stepNumber: 5,
    title: 'Merkle Tree Multi-Specimen Case Seal',
    tab: 'merkle',
    cueNote:
      'Show how multiple specimens are bound into a single Merkle root, allowing privacy-preserving selective proofs in court.',
    icon: GitCommit,
  },
  {
    stepNumber: 6,
    title: 'AI Auditor Brief & Court-Admissible PDF Report',
    tab: 'ai_assistant',
    cueNote:
      'Click "Explain This Verification" in English or Marathi, then export the formal PDF report with the cryptographic self-integrity seal.',
    icon: Bot,
  },
];

interface DemoTourBarProps {
  currentStepIndex: number;
  onSelectStep: (index: number) => void;
  onClose: () => void;
}

export const DemoTourBar: React.FC<DemoTourBarProps> = ({
  currentStepIndex,
  onSelectStep,
  onClose,
}) => {
  const currentStep = DEMO_STEPS[currentStepIndex] || DEMO_STEPS[0];
  const StepIcon = currentStep.icon;

  return (
    <div className="fixed bottom-4 left-4 right-4 z-50 max-w-4xl mx-auto bg-slate-900/95 border border-cyan-500/60 rounded-2xl p-4 shadow-2xl backdrop-blur-md animate-in slide-in-from-bottom-4 duration-200 font-mono text-xs text-slate-200">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-cyan-950 border border-cyan-500 text-cyan-400">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-slate-100">
                Presentation Demo Tour ({currentStepIndex + 1}/{DEMO_STEPS.length})
              </span>
              <span className="text-[10px] text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                Under 3 Minutes
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Step {currentStep.stepNumber}: <strong className="text-cyan-300">{currentStep.title}</strong>
            </p>
          </div>
        </div>

        <button
          onClick={onClose}
          className="text-slate-400 hover:text-slate-200 p-1 self-start sm:self-auto cursor-pointer"
          title="Exit Tour"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-start gap-2 text-slate-300 text-xs">
          <span className="text-cyan-400 font-bold shrink-0">Cue:</span>
          <p className="leading-relaxed">{currentStep.cueNote}</p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => onSelectStep(Math.max(0, currentStepIndex - 1))}
            disabled={currentStepIndex === 0}
            className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300 text-xs font-mono transition-colors flex items-center gap-1"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
            <span>Prev</span>
          </button>

          {currentStepIndex < DEMO_STEPS.length - 1 ? (
            <button
              onClick={() => onSelectStep(currentStepIndex + 1)}
              className="px-4 py-1.5 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono transition-colors flex items-center gap-1 shadow-sm shadow-cyan-950"
            >
              <span>Next Step</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          ) : (
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs font-mono transition-colors flex items-center gap-1"
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Finish Tour</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
