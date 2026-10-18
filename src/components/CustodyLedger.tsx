/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Lock,
  PlusCircle,
  FileCode,
  Copy,
  Check,
  RefreshCw,
  ExternalLink,
  RotateCcw,
  Fingerprint,
} from 'lucide-react';
import { CustodyBlock, ForensicCase, ChainVerificationReport } from '../types/forensics';

interface CustodyLedgerProps {
  currentCase: ForensicCase;
  verificationReport: ChainVerificationReport | null;
  isVerifying: boolean;
  onVerifyChain: () => void;
  onOpenTamperModal: () => void;
  onOpenAddEventModal: () => void;
  onRestoreBackup: () => void;
  onOpenBlockDetail: (block: CustodyBlock) => void;
  hasBackup: boolean;
}

export const CustodyLedger: React.FC<CustodyLedgerProps> = ({
  currentCase,
  verificationReport,
  isVerifying,
  onVerifyChain,
  onOpenTamperModal,
  onOpenAddEventModal,
  onRestoreBackup,
  onOpenBlockDetail,
  hasBackup,
}) => {
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [showEvidenceModal, setShowEvidenceModal] = useState<boolean>(false);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const getEventBadgeColor = (type: CustodyBlock['eventType']) => {
    switch (type) {
      case 'COLLECTED':
        return 'text-sky-400 bg-sky-950/70 border-sky-800/80';
      case 'TRANSFERRED':
        return 'text-indigo-400 bg-indigo-950/70 border-indigo-800/80';
      case 'ANALYZED':
        return 'text-cyan-400 bg-cyan-950/70 border-cyan-800/80';
      case 'STORED':
        return 'text-amber-400 bg-amber-950/70 border-amber-800/80';
      case 'RELEASED':
        return 'text-purple-400 bg-purple-950/70 border-purple-800/80';
      case 'SEALED':
        return 'text-emerald-400 bg-emerald-950/70 border-emerald-800/80';
      case 'WATERMARKED':
        return 'text-amber-300 bg-amber-950/70 border-amber-700/80';
      case 'VERIFIED':
        return 'text-emerald-300 bg-emerald-950/80 border-emerald-600/80';
      case 'REPORT_GENERATED':
        return 'text-sky-300 bg-sky-950/80 border-sky-600/80';
      default:
        return 'text-slate-400 bg-slate-900 border-slate-700';
    }
  };

  return (
    <div className="max-w-5xl mx-auto py-8 px-4 sm:px-6 space-y-8">
      {/* Evidence Summary Card */}
      <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 shadow-lg">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            {/* Thumbnail */}
            <div
              onClick={() => setShowEvidenceModal(true)}
              className="relative w-20 h-20 rounded-lg overflow-hidden bg-slate-950 border border-slate-800 cursor-pointer group shrink-0"
              title="Click to view specimen preview"
            >
              <img
                src={currentCase.evidence.imageDataUrl}
                alt={currentCase.evidence.evidenceId}
                className="w-full h-full object-cover group-hover:scale-105 transition-transform"
              />
              <div className="absolute inset-0 bg-cyan-950/20 group-hover:bg-transparent transition-colors" />
            </div>

            <div className="space-y-1">
              <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
                <span>CASE REF: {currentCase.caseId}</span>
                <span aria-hidden="true">·</span>
                <span>TAG: {currentCase.evidence.evidenceId}</span>
              </div>
              <h2 className="text-base font-semibold text-slate-100">
                {currentCase.caseTitle || currentCase.evidence.description}
              </h2>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400">
                <span>Collector: <strong className="text-slate-300">{currentCase.evidence.collectorName}</strong></span>
                <span aria-hidden="true">·</span>
                <span>Recovered: {new Date(currentCase.evidence.timestamp).toLocaleString()}</span>
              </div>
            </div>
          </div>

          {/* Evidence Root SHA-256 Badge */}
          <div className="w-full md:w-auto p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <div className="flex items-center justify-between gap-4">
              <span className="text-[11px] font-mono uppercase text-slate-400 flex items-center gap-1.5">
                <Fingerprint className="w-3.5 h-3.5 text-cyan-400" />
                <span>Evidence SHA-256 Root Hash</span>
              </span>
              <button
                onClick={() => handleCopy(currentCase.evidence.sha256Hash, 'rootHash')}
                className="text-[11px] font-mono text-slate-400 hover:text-cyan-400 flex items-center gap-1"
              >
                {copiedHash === 'rootHash' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copiedHash === 'rootHash' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <div className="font-mono text-xs text-cyan-300 break-all select-all">
              {currentCase.evidence.sha256Hash}
            </div>
          </div>
        </div>
      </div>

      {/* Action Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/60 border border-slate-800">
        <div>
          <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <span>Cryptographic Custody Timeline</span>
            <span className="text-xs font-mono text-slate-400">
              ({currentCase.blocks.length} blocks chained)
            </span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Each custody event is cryptographically sealed with the preceding block’s hash and signed via ECDSA P-256.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Verify Chain Button */}
          <button
            onClick={onVerifyChain}
            disabled={isVerifying}
            className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 rounded-md transition-colors flex items-center gap-2 shadow-sm shadow-cyan-950"
          >
            {isVerifying ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Verifying Cryptography...</span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>Verify Chain</span>
              </>
            )}
          </button>

          {/* Tamper with a Block demo button */}
          <button
            onClick={onOpenTamperModal}
            className="px-3.5 py-2 text-xs font-semibold text-rose-300 bg-rose-950/70 border border-rose-800 hover:bg-rose-900/80 rounded-md transition-colors flex items-center gap-2"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            <span>Tamper with a Block (Demo)</span>
          </button>

          {/* Restore clean backup */}
          {hasBackup && (
            <button
              onClick={onRestoreBackup}
              title="Re-seal and restore ledger to valid untampered state"
              className="px-3 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-md transition-colors flex items-center gap-1.5 border border-slate-700"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Restore Valid State</span>
            </button>
          )}

          {/* Add Custody Event */}
          <button
            onClick={onOpenAddEventModal}
            className="px-3.5 py-2 text-xs font-semibold text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md transition-colors flex items-center gap-1.5"
          >
            <PlusCircle className="w-3.5 h-3.5 text-cyan-400" />
            <span>Add Custody Event</span>
          </button>
        </div>
      </div>

      {/* Verification Status Banner (if audit has run) */}
      {verificationReport && (
        <div
          className={`p-4 rounded-xl border flex items-start gap-3 ${
            verificationReport.isChainValid
              ? 'bg-emerald-950/30 border-emerald-600/50 text-emerald-200'
              : 'bg-rose-950/40 border-rose-600/80 text-rose-200 shadow-lg shadow-rose-950/40 animate-pulse'
          }`}
        >
          {verificationReport.isChainValid ? (
            <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-400 mt-0.5" />
          ) : (
            <AlertTriangle className="w-5 h-5 shrink-0 text-rose-400 mt-0.5" />
          )}

          <div className="flex-1 space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-sm">
                {verificationReport.isChainValid
                  ? 'CHAIN OF CUSTODY VERIFIED: COMPLETE INTEGRITY CONFIRMED'
                  : 'INTEGRITY BREACH DETECTED: ADULTERATED BLOCK DETECTED'}
              </span>
              <span className="text-[11px] font-mono opacity-80">
                Verified: {new Date(verificationReport.verifiedAt).toLocaleTimeString()}
              </span>
            </div>
            <p className="text-xs opacity-90 leading-relaxed">
              {verificationReport.auditSummary}
            </p>
          </div>
        </div>
      )}

      {/* Vertical Timeline of Blocks */}
      <div className="relative pl-6 sm:pl-8 space-y-8 before:absolute before:left-3 before:top-4 before:bottom-4 before:w-0.5 before:bg-slate-800">
        {currentCase.blocks.map((block, idx) => {
          const status = verificationReport?.blockStatuses.find(
            (s) => s.blockIndex === block.blockIndex
          );
          const isBroken = status !== undefined && !status.isValid;
          const isDirectBroken =
            verificationReport?.firstBrokenBlockIndex === block.blockIndex;
          const isCascadeBroken =
            verificationReport?.firstBrokenBlockIndex !== null &&
            verificationReport?.firstBrokenBlockIndex !== undefined &&
            block.blockIndex > verificationReport.firstBrokenBlockIndex;

          const blockCardStyle = isBroken
            ? 'bg-rose-950/30 border-rose-600/90 shadow-rose-950/50 ring-1 ring-rose-500/50'
            : status?.isValid
            ? 'bg-slate-900/90 border-emerald-500/40 shadow-emerald-950/20'
            : 'bg-slate-900/90 border-slate-800';

          return (
            <div key={block.blockIndex} className="relative group">
              {/* Timeline Node Indicator */}
              <div
                className={`absolute -left-6 sm:-left-8 top-6 -translate-x-1/2 w-7 h-7 rounded-full flex items-center justify-center font-mono text-xs font-bold border-2 z-10 transition-colors ${
                  isBroken
                    ? 'bg-rose-600 border-rose-300 text-white shadow-lg shadow-rose-900/80 animate-bounce'
                    : status?.isValid
                    ? 'bg-emerald-950 border-emerald-400 text-emerald-300'
                    : 'bg-slate-950 border-cyan-500/60 text-cyan-400'
                }`}
              >
                {block.blockIndex}
              </div>

              {/* Block Card */}
              <div
                className={`rounded-xl border p-5 sm:p-6 transition-all duration-200 ${blockCardStyle}`}
              >
                {/* Broken Link Warning Banner */}
                {isBroken && (
                  <div className="mb-4 p-3 rounded-lg bg-rose-600 text-white font-mono text-xs font-bold tracking-wider flex items-center justify-between shadow-md">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 animate-spin" />
                      <span>
                        BROKEN LINK {isCascadeBroken ? '(CHAIN SEVERED UPSTREAM)' : '(PRIMARY INTEGRITY BREACH)'}
                      </span>
                    </div>
                    <span className="text-[11px] bg-rose-900/80 px-2 py-0.5 rounded">
                      BLOCK #{block.blockIndex} INVALID
                    </span>
                  </div>
                )}

                {/* Error diagnostics list if broken */}
                {isBroken && status && status.errorMessages.length > 0 && (
                  <div className="mb-4 p-3 rounded-lg bg-rose-950/80 border border-rose-700/80 space-y-1 text-xs font-mono text-rose-300">
                    <span className="font-semibold text-rose-200 block text-[11px] uppercase tracking-wider">
                      Forensic Audit Violations:
                    </span>
                    <ul className="list-disc list-inside space-y-0.5 text-[11px]">
                      {status.errorMessages.map((msg, i) => (
                        <li key={i}>{msg}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Block Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800/80">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-mono font-bold text-slate-300">
                      BLOCK #{block.blockIndex}
                    </span>
                    <span
                      className={`text-[11px] font-mono px-2 py-0.5 rounded border uppercase font-semibold ${getEventBadgeColor(
                        block.eventType
                      )}`}
                    >
                      {block.eventType}
                    </span>
                    {block.blockIndex === 0 && (
                      <span className="text-[10px] font-mono uppercase bg-cyan-950 text-cyan-400 border border-cyan-800 px-1.5 py-0.5 rounded">
                        Genesis Anchor
                      </span>
                    )}
                  </div>

                  <div className="text-xs text-slate-400 font-mono">
                    <span>{block.timestamp}</span>
                  </div>
                </div>

                {/* Event & Actor Info */}
                <div className="py-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Left Column: Actor & Details */}
                  <div className="space-y-3">
                    <div>
                      <span className="text-[11px] uppercase font-mono text-slate-500 block">
                        Forensic Custodian / Signer
                      </span>
                      <div className="text-sm font-semibold text-slate-100 mt-0.5">
                        {block.actorName}
                      </div>
                      <div className="text-xs text-slate-400">
                        {block.actorRole} · {block.actorAgency}
                      </div>
                    </div>

                    <div>
                      <span className="text-[11px] uppercase font-mono text-slate-500 block">
                        Action Executed
                      </span>
                      <div className="text-xs text-slate-200 font-medium mt-0.5">
                        {block.details.action}
                      </div>
                      {block.details.facilityLocation && (
                        <div className="text-xs text-slate-400 mt-0.5">
                          Location: {block.details.facilityLocation}
                        </div>
                      )}
                    </div>

                    {block.details.toolOrMethodUsed && (
                      <div>
                        <span className="text-[11px] uppercase font-mono text-slate-500 block">
                          Hardware / Tool Used
                        </span>
                        <div className="text-xs font-mono text-slate-300 mt-0.5">
                          {block.details.toolOrMethodUsed}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Right Column: Custody Notes & Authorization */}
                  <div className="space-y-3">
                    <div>
                      <span className="text-[11px] uppercase font-mono text-slate-500 block">
                        Custodial Examination Notes
                      </span>
                      <p className="text-xs text-slate-300 mt-0.5 leading-relaxed bg-slate-950/50 p-2.5 rounded border border-slate-800/80">
                        {block.details.notes}
                      </p>
                    </div>

                    {block.details.authorizationReference && (
                      <div className="text-xs text-slate-400">
                        <span className="font-mono text-slate-500 text-[11px] uppercase">
                          Legal Auth:
                        </span>{' '}
                        <span className="font-mono text-slate-300">
                          {block.details.authorizationReference}
                        </span>
                      </div>
                    )}

                    {block.details.recipientName && (
                      <div className="text-xs text-slate-400">
                        <span className="font-mono text-slate-500 text-[11px] uppercase">
                          Transferred To:
                        </span>{' '}
                        <span className="text-slate-300">
                          {block.details.recipientName}
                        </span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Cryptographic Linkage Panel */}
                <div className="pt-4 border-t border-slate-800/80 space-y-2.5">
                  {/* Previous Block Hash */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-xs font-mono">
                    <span className="text-slate-500 text-[11px] uppercase shrink-0">
                      Previous Block Hash:
                    </span>
                    <div className="flex items-center gap-2">
                      <span className="text-slate-400 break-all text-[11px]">
                        {block.previousHash}
                      </span>
                      <button
                        onClick={() => handleCopy(block.previousHash, `prev-${block.blockIndex}`)}
                        className="text-slate-500 hover:text-cyan-400 p-0.5 shrink-0"
                        title="Copy previous hash"
                      >
                        {copiedHash === `prev-${block.blockIndex}` ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Current Block Hash */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-xs font-mono">
                    <span className="text-cyan-400 text-[11px] uppercase shrink-0 font-semibold">
                      Current Block Hash:
                    </span>
                    <div className="flex items-center gap-2">
                      <span className="text-cyan-300 break-all text-[11px] font-semibold">
                        {block.currentHash}
                      </span>
                      <button
                        onClick={() => handleCopy(block.currentHash, `curr-${block.blockIndex}`)}
                        className="text-slate-500 hover:text-cyan-400 p-0.5 shrink-0"
                        title="Copy current block hash"
                      >
                        {copiedHash === `curr-${block.blockIndex}` ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                  </div>

                  {/* ECDSA Signature Snippet & Inspection Button */}
                  <div className="pt-2 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
                    <div className="flex items-center gap-2 text-slate-400 text-[11px]">
                      <Lock className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      <span>ECDSA P-256 Sig:</span>
                      <span className="text-emerald-400/90 truncate max-w-[200px] sm:max-w-[260px]">
                        {block.signatureHex.substring(0, 32)}...
                      </span>
                    </div>

                    <button
                      onClick={() => onOpenBlockDetail(block)}
                      className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 transition-colors self-start sm:self-auto"
                    >
                      <FileCode className="w-3.5 h-3.5" />
                      <span>Inspect Cryptographic Anatomy</span>
                      <ExternalLink className="w-3 h-3" />
                    </button>
                  </div>
                </div>
              </div>

              {/* Cryptographic Hash Cable connecting to next block */}
              {idx < currentCase.blocks.length - 1 && (
                <div className="py-2 pl-4 flex items-center gap-2 text-[11px] font-mono text-slate-500">
                  <div
                    className={`h-4 w-0.5 ${
                      isBroken ? 'bg-rose-500' : 'bg-cyan-500/40'
                    }`}
                  />
                  <span
                    className={
                      isBroken
                        ? 'text-rose-400 font-semibold'
                        : 'text-slate-500'
                    }
                  >
                    {isBroken
                      ? '✕ CRYPTOGRAPHIC LINK BROKEN'
                      : '↳ Hash-linked pointer to Block #' + (idx + 1)}
                  </span>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Specimen Preview Modal */}
      {showEvidenceModal && (
        <div
          onClick={() => setShowEvidenceModal(false)}
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/90 backdrop-blur-md cursor-pointer"
        >
          <div className="max-w-2xl max-h-[85vh] p-2 bg-slate-900 border border-slate-700 rounded-xl overflow-hidden">
            <img
              src={currentCase.evidence.imageDataUrl}
              alt="Evidence Specimen"
              className="max-h-[75vh] w-auto mx-auto object-contain rounded"
            />
            <div className="p-3 text-center text-xs font-mono text-slate-300">
              Evidence Tag: {currentCase.evidence.evidenceId} • Click anywhere to close
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
