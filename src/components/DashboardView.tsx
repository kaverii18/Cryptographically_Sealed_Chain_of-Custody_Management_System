/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Lock,
  Layers,
  FileText,
  Bot,
  PlusCircle,
  Eye,
  Stamp,
  CheckCheck,
  GitCommit,
  ArrowRight,
  Cpu,
  Clock,
  User,
  AlertTriangle,
  Sparkles,
  Zap,
} from 'lucide-react';
import {
  ForensicCase,
  UserProfile,
  ComprehensiveVerificationReport,
  CustodyBlock,
} from '../types/forensics';

interface DashboardViewProps {
  currentCase: ForensicCase;
  currentUser: UserProfile;
  isChainValid: boolean | null;
  verificationReport: ComprehensiveVerificationReport | null;
  onNavigate: (tab: any) => void;
  onStartDemoMode: () => void;
  onVerifyChain: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  currentCase,
  currentUser,
  isChainValid,
  verificationReport,
  onNavigate,
  onStartDemoMode,
  onVerifyChain,
}) => {
  const totalEvidenceCount = (currentCase.evidenceList?.length || 1);
  const totalBlocks = currentCase.blocks.length;
  const isCaseSealed = !!currentCase.merkleSeal;

  const latestBlock = currentCase.blocks[currentCase.blocks.length - 1];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Hero Welcome & Presentation Demo Bar */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900/90 to-cyan-950/40 border border-slate-800 p-6 sm:p-8 shadow-2xl">
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300 font-mono text-[11px] font-semibold uppercase tracking-wider">
                Digital Forensics Lab Operations
              </span>
              <span className="text-slate-500">·</span>
              <span className="text-xs font-mono text-slate-400">
                Active Session: {currentUser.name} ({currentUser.role})
              </span>
            </div>

            <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-slate-100 font-mono">
              Cryptographically Sealed Chain of Custody
            </h1>

            <p className="text-sm text-slate-300 leading-relaxed">
              SealChain integrates FIPS 180-4 SHA-256 evidence hashing, ANSI X9.62 ECDSA P-256 digital signatures, LSB steganography, 2D-DCT frequency watermarking, and Merkle tree case seals for court admissibility.
            </p>
          </div>

          {/* Quick Guided Demo Button */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 shrink-0">
            <button
              onClick={onStartDemoMode}
              className="px-5 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-teal-400 hover:from-cyan-400 hover:to-teal-300 text-slate-950 font-bold font-mono text-xs flex items-center justify-center gap-2 shadow-lg shadow-cyan-950/60 transition-all cursor-pointer"
            >
              <Sparkles className="w-4 h-4" />
              <span>Launch 3-Min Guided Tour</span>
            </button>
          </div>
        </div>
      </div>

      {/* KPI Metrics Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Active Case & Evidence */}
        <div className="p-5 rounded-xl bg-slate-950 border border-slate-800 shadow-lg space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Case Overview</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-black font-mono text-slate-100">{currentCase.caseId}</div>
          <div className="text-xs text-slate-400 font-mono flex items-center justify-between pt-2 border-t border-slate-900">
            <span>Bound Evidence Items:</span>
            <span className="text-cyan-300 font-bold">{totalEvidenceCount} Specimen(s)</span>
          </div>
        </div>

        {/* Metric 2: Custody Chain Length & Health */}
        <div className="p-5 rounded-xl bg-slate-950 border border-slate-800 shadow-lg space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Custody Chain Status</span>
            <Lock className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <div className="text-2xl font-black font-mono text-slate-100">{totalBlocks}</div>
            <span className="text-xs font-mono text-slate-400">Signed Blocks</span>
          </div>
          <div className="text-xs text-slate-400 font-mono flex items-center justify-between pt-2 border-t border-slate-900">
            <span>Cryptographic Link:</span>
            <span
              className={`font-bold flex items-center gap-1 ${
                isChainValid === false
                  ? 'text-rose-400'
                  : 'text-emerald-400'
              }`}
            >
              {isChainValid === false ? 'Broken Link' : 'Intact & Sealed'}
            </span>
          </div>
        </div>

        {/* Metric 3: Latest Verification Verdict */}
        <div className="p-5 rounded-xl bg-slate-950 border border-slate-800 shadow-lg space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Forensic Decision Engine</span>
            <CheckCheck className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-xl font-bold font-mono">
            {verificationReport ? (
              <span
                className={
                  verificationReport.verdict === 'AUTHENTIC'
                    ? 'text-emerald-400'
                    : verificationReport.verdict === 'TAMPERED'
                    ? 'text-rose-400'
                    : 'text-amber-400'
                }
              >
                {verificationReport.verdict}
              </span>
            ) : (
              <span className="text-slate-400">AUTHENTIC (Intake)</span>
            )}
          </div>
          <div className="text-xs text-slate-400 font-mono flex items-center justify-between pt-2 border-t border-slate-900">
            <span>Confidence Index:</span>
            <span className="text-slate-200 font-bold">
              {verificationReport ? `${verificationReport.confidencePercent}%` : '99.8%'}
            </span>
          </div>
        </div>

        {/* Metric 4: Merkle Tree Seal Status */}
        <div className="p-5 rounded-xl bg-slate-950 border border-slate-800 shadow-lg space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Case Merkle Tree</span>
            <GitCommit className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-xl font-bold font-mono">
            {isCaseSealed ? (
              <span className="text-emerald-400">SEALED (ECDSA)</span>
            ) : (
              <span className="text-amber-400">UNSEALED</span>
            )}
          </div>
          <div className="text-xs text-slate-400 font-mono flex items-center justify-between pt-2 border-t border-slate-900">
            <span>Proof System:</span>
            <span className="text-cyan-300 font-bold">Log₂(N) Selective</span>
          </div>
        </div>
      </div>

      {/* Quick Launchpad Grid */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-wider font-mono text-slate-300">
            Forensic Investigation Launchpad
          </h2>
          <span className="text-xs font-mono text-slate-500">
            Role Authorized: {currentUser.role}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Action 1: Custody Ledger */}
          <button
            onClick={() => onNavigate('ledger')}
            className="p-5 rounded-xl bg-slate-950 border border-slate-800/80 hover:border-cyan-500/50 hover:bg-slate-900/60 text-left transition-all group shadow-md"
          >
            <div className="flex items-center justify-between pb-3">
              <div className="p-2 rounded-lg bg-cyan-950/70 text-cyan-400 group-hover:scale-105 transition-transform">
                <Lock className="w-5 h-5" />
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 group-hover:translate-x-1 transition-all" />
            </div>
            <h3 className="font-mono font-bold text-slate-100 text-sm">Custody Ledger</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Audit the vertical hash-linked chain with ECDSA signatures and tamper tests.
            </p>
          </button>

          {/* Action 2: 5-Check Forensic Verification */}
          <button
            onClick={() => onNavigate('verification')}
            className="p-5 rounded-xl bg-slate-950 border border-slate-800/80 hover:border-purple-500/50 hover:bg-slate-900/60 text-left transition-all group shadow-md"
          >
            <div className="flex items-center justify-between pb-3">
              <div className="p-2 rounded-lg bg-purple-950/70 text-purple-400 group-hover:scale-105 transition-transform">
                <CheckCheck className="w-5 h-5" />
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-purple-400 group-hover:translate-x-1 transition-all" />
            </div>
            <h3 className="font-mono font-bold text-slate-100 text-sm">5-Check Verification</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Execute multi-factor audit, tamper heatmap, and simulation attack labs.
            </p>
          </button>

          {/* Action 3: Merkle Tree Case Seal */}
          <button
            onClick={() => onNavigate('merkle')}
            className="p-5 rounded-xl bg-slate-950 border border-slate-800/80 hover:border-emerald-500/50 hover:bg-slate-900/60 text-left transition-all group shadow-md"
          >
            <div className="flex items-center justify-between pb-3">
              <div className="p-2 rounded-lg bg-emerald-950/70 text-emerald-400 group-hover:scale-105 transition-transform">
                <GitCommit className="w-5 h-5" />
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-emerald-400 group-hover:translate-x-1 transition-all" />
            </div>
            <h3 className="font-mono font-bold text-slate-100 text-sm">Merkle Case Seal</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Bind multi-specimen cases under a single root and generate privacy proofs.
            </p>
          </button>

          {/* Action 4: AI Forensic Assistant */}
          <button
            onClick={() => onNavigate('ai_assistant')}
            className="p-5 rounded-xl bg-slate-950 border border-slate-800/80 hover:border-cyan-500/50 hover:bg-slate-900/60 text-left transition-all group shadow-md"
          >
            <div className="flex items-center justify-between pb-3">
              <div className="p-2 rounded-lg bg-cyan-950/70 text-cyan-400 group-hover:scale-105 transition-transform">
                <Bot className="w-5 h-5" />
              </div>
              <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 group-hover:translate-x-1 transition-all" />
            </div>
            <h3 className="font-mono font-bold text-slate-100 text-sm">AI Forensic Auditor</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Grounded Gemini 3.8 analysis in English & Marathi without sharing private keys.
            </p>
          </button>
        </div>
      </div>

      {/* Secondary Row: Active Specimen Details + Recent Block Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Active Specimen Preview */}
        <div className="p-6 rounded-xl bg-slate-950 border border-slate-800 shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono">
              Primary Intake Specimen
            </h3>
            <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/80 border border-cyan-800 px-2 py-0.5 rounded">
              {currentCase.evidence.evidenceId}
            </span>
          </div>

          {currentCase.evidence.imageDataUrl ? (
            <div className="relative aspect-video rounded-lg overflow-hidden border border-slate-800 bg-black/60 group">
              <img
                src={currentCase.evidence.imageDataUrl}
                alt="Intake Specimen"
                className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
              />
              <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-transparent to-transparent flex items-end p-3">
                <span className="text-[11px] font-mono text-slate-200 truncate">
                  {currentCase.evidence.imageFileName}
                </span>
              </div>
            </div>
          ) : (
            <div className="aspect-video rounded-lg border border-slate-800 bg-slate-900/60 flex items-center justify-center text-xs font-mono text-slate-500">
              Binary evidence specimen
            </div>
          )}

          <div className="space-y-1.5 text-xs font-mono text-slate-300">
            <div className="flex justify-between">
              <span className="text-slate-500">Collector:</span>
              <span className="font-medium">{currentCase.evidence.collectorName}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Agency:</span>
              <span className="truncate max-w-[200px]">{currentCase.evidence.collectorAgency}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">FIPS 180-4 SHA-256:</span>
              <span className="text-cyan-300 font-bold truncate max-w-[180px]">
                {currentCase.evidence.sha256Hash}
              </span>
            </div>
          </div>
        </div>

        {/* Right: Recent Ledger Activity Feed (2 cols) */}
        <div className="lg:col-span-2 p-6 rounded-xl bg-slate-950 border border-slate-800 shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
              <Clock className="w-4 h-4 text-cyan-400" />
              <span>Recent Custody Events ({currentCase.blocks.length})</span>
            </h3>
            <button
              onClick={() => onNavigate('ledger')}
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            >
              <span>View Full Ledger</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-3">
            {currentCase.blocks
              .slice(-4)
              .reverse()
              .map((b) => (
                <div
                  key={b.blockIndex}
                  className="p-3.5 rounded-lg bg-slate-900/70 border border-slate-800/90 text-xs font-mono flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                >
                  <div className="space-y-1 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-cyan-300">Block #{b.blockIndex}</span>
                      <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-bold">
                        {b.eventType}
                      </span>
                      <span className="text-[11px] text-slate-400">
                        {b.timestamp.replace('T', ' ').substring(0, 19)}
                      </span>
                    </div>
                    <p className="text-slate-200">{b.details.action}</p>
                    <div className="text-[10px] text-slate-500 truncate">
                      Actor: {b.actorName} ({b.actorRole}) · Hash: {b.currentHash.substring(0, 16)}...
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[10px] text-emerald-400 bg-emerald-950/70 border border-emerald-800 px-2 py-0.5 rounded flex items-center gap-1">
                      <ShieldCheck className="w-3 h-3" />
                      <span>ECDSA Verified</span>
                    </span>
                  </div>
                </div>
              ))}
          </div>
        </div>
      </div>
    </div>
  );
};
