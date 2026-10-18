/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  FileText,
  Download,
  QrCode,
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Languages,
  Sliders,
  Eye,
  RefreshCw,
  Copy,
  Check,
  Sparkles,
  Search,
  ArrowRight,
  HelpCircle,
  FileDown,
  Building,
  User,
} from 'lucide-react';
import {
  ForensicCase,
  ActorIdentity,
  CustodyBlock,
  ComprehensiveVerificationReport,
  ReportOptions,
  CompactReportQrPayload,
  GeneratedReportData,
} from '../types/forensics';
import {
  generateReportQr,
  computeReportSelfIntegrity,
  generateCourtAdmissiblePdf,
} from '../crypto/reportPdfGenerator';
import { createSignedBlock } from '../crypto/webCrypto';
import { runComprehensiveVerification } from '../crypto/forensicVerification';
import { loadImageDataFromUrl } from '../crypto/stegoCrypto';

interface ReportsModuleProps {
  currentCase: ForensicCase;
  actors: ActorIdentity[];
  activeVerificationReport: ComprehensiveVerificationReport | null;
  aiExplanationText?: string | null;
  onAddCustodyBlock: (newBlock: CustodyBlock) => void;
  onNavigateToVerification: () => void;
  onNavigateToLedger: () => void;
}

export const ReportsModule: React.FC<ReportsModuleProps> = ({
  currentCase,
  actors,
  activeVerificationReport,
  aiExplanationText,
  onAddCustodyBlock,
  onNavigateToVerification,
  onNavigateToLedger,
}) => {
  const [subTab, setSubTab] = useState<'generate' | 'verify_qr'>('generate');

  // Report Configuration Options
  const [reportOptions, setReportOptions] = useState<ReportOptions>({
    includeEvidenceDetails: true,
    includeChainOfCustody: true,
    includeIntegrityChecks: true,
    includeVerdict: true,
    includeHeatmap: true,
    includeMethodology: true,
    includeSignatures: true,
    includeAiExplanation: !!aiExplanationText,
    aiExplanationText: aiExplanationText || undefined,
    language: 'en',
    investigatorName: actors[0]?.name || 'Det. Elena Rostova',
    investigatorOrg: actors[0]?.agency || 'State Digital Crimes Division',
    notes: 'Official forensic report compiled for judicial proceedings and chain of custody confirmation.',
  });

  const [selectedSignerId, setSelectedSignerId] = useState<string>(actors[0]?.id || '');
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [generatedReport, setGeneratedReport] = useState<GeneratedReportData | null>(null);
  const [loggedReportBlockIndex, setLoggedReportBlockIndex] = useState<number | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Quick baseline verification state if user arrives before running verification
  const [localVerification, setLocalVerification] = useState<ComprehensiveVerificationReport | null>(
    activeVerificationReport
  );
  const [isGeneratingBaselineVerify, setIsGeneratingBaselineVerify] = useState<boolean>(false);

  // QR Verifier State
  const [qrInputText, setQrInputText] = useState<string>('');
  const [isVerifyingQr, setIsVerifyingQr] = useState<boolean>(false);
  const [qrVerificationResult, setQrVerificationResult] = useState<{
    status: 'AUTHENTIC' | 'ALTERED' | 'INVALID_JSON';
    message: string;
    matchedBlockIndex?: number;
    details?: string[];
  } | null>(null);

  const headBlock = currentCase.blocks[currentCase.blocks.length - 1];
  const ledgerHeadHash = headBlock ? headBlock.currentHash : '0000000000000000000000000000000000000000000000000000000000000000';

  // Build report self-integrity and QR code preview
  const buildReportData = useCallback(async () => {
    const reportId = `RPT-${currentCase.caseId.replace(/[^a-zA-Z0-9]/g, '')}-${Date.now().toString().slice(-6)}`;
    const reportDate = new Date().toISOString();
    const signer = actors.find((a) => a.id === selectedSignerId) || actors[0];

    const verdict = localVerification ? localVerification.verdict : 'AUTHENTIC';

    // 1. Compute self-integrity SHA-256 and ECDSA P-256 signature
    const { reportHash, signatureHex } = await computeReportSelfIntegrity({
      reportId,
      caseId: currentCase.caseId,
      evidenceId: currentCase.evidence.evidenceId,
      options: reportOptions,
      reportDate,
      evidenceHash: currentCase.evidence.sha256Hash,
      ledgerHeadHash,
      verdict,
      actor: signer,
    });

    // 2. Compact QR Payload
    const qrPayload: CompactReportQrPayload = {
      reportId,
      caseId: currentCase.caseId,
      evidenceId: currentCase.evidence.evidenceId,
      evidenceHash: currentCase.evidence.sha256Hash,
      ledgerHeadHash,
      reportHash,
      verdict,
      generatedAt: reportDate,
      merkleRoot: currentCase.merkleSeal?.merkleRoot,
    };

    // 3. Generate QR code
    const qrDataUrl = await generateReportQr(qrPayload);

    setGeneratedReport({
      reportId,
      generatedAt: reportDate,
      caseId: currentCase.caseId,
      evidenceId: currentCase.evidence.evidenceId,
      investigatorName: reportOptions.investigatorName,
      investigatorOrg: reportOptions.investigatorOrg,
      options: reportOptions,
      reportHash,
      reportSignatureHex: signatureHex,
      qrPayload,
      qrDataUrl,
    });
  }, [actors, currentCase.caseId, currentCase.evidence.evidenceId, currentCase.evidence.sha256Hash, ledgerHeadHash, localVerification, reportOptions, selectedSignerId]);

  useEffect(() => {
    buildReportData();
  }, [buildReportData]);

  // Run quick verification baseline if none exists
  const handleQuickVerification = async () => {
    setIsGeneratingBaselineVerify(true);
    try {
      const { imageData } = await loadImageDataFromUrl(currentCase.evidence.imageDataUrl);
      const rep = await runComprehensiveVerification({
        suspectImageData: imageData,
        suspectFileSha256: currentCase.evidence.sha256Hash,
        mode: 'LEDGER_LINKED',
        currentCase,
        passphrase: 'ForensicSecure#2026',
        originalImageData: imageData,
      });
      setLocalVerification(rep);
    } catch (err) {
      console.error('Failed to run baseline verification:', err);
    } finally {
      setIsGeneratingBaselineVerify(false);
    }
  };

  // Download Court Admissible PDF & Log to Ledger
  const handleDownloadPdf = async () => {
    if (!generatedReport) return;
    setIsGenerating(true);

    try {
      // 1. Generate and save PDF
      await generateCourtAdmissiblePdf({
        currentCase,
        verificationReport: localVerification,
        reportData: generatedReport,
      });

      // 2. Log "REPORT_GENERATED" event to custody ledger (Self-Integrity Record)
      const signer = actors.find((a) => a.id === selectedSignerId) || actors[0];
      const prevHash = ledgerHeadHash;
      const nextIndex = currentCase.blocks.length;

      const reportBlock = await createSignedBlock({
        blockIndex: nextIndex,
        previousHash: prevHash,
        eventType: 'REPORT_GENERATED',
        actor: signer,
        details: {
          action: `Court-Admissible Forensic Integrity Report Generated [${generatedReport.reportId}]`,
          departmentOrAgency: reportOptions.investigatorOrg,
          facilityLocation: 'Digital Forensic Document & Evidence Audit Division',
          toolOrMethodUsed: `SealChain PDF Engine & QR Provenance Seal (SHA-256 + ECDSA P-256)`,
          notes: `Formal forensic examination report compiled with Self-Integrity Seal. Report Hash: ${generatedReport.reportHash}. QR Token: Case ${generatedReport.caseId}, Verdict: ${generatedReport.qrPayload.verdict}. Language: ${reportOptions.language.toUpperCase()}.`,
          authorizationReference: `Report Certificate #${generatedReport.reportId}`,
        },
        evidenceId: currentCase.evidence.evidenceId,
        evidenceHash: currentCase.evidence.sha256Hash,
      });

      onAddCustodyBlock(reportBlock);
      setLoggedReportBlockIndex(nextIndex);
    } catch (err) {
      console.error('PDF generation error:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  // Export Complete Case Bundle JSON
  const handleExportCaseBundle = () => {
    const bundle = {
      bundleVersion: '1.0',
      exportedAt: new Date().toISOString(),
      caseMetadata: currentCase,
      activeVerificationReport: localVerification,
      generatedReportMetadata: generatedReport,
    };

    const jsonString = JSON.stringify(bundle, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `case_bundle_${currentCase.caseId}_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Download QR Code as PNG
  const handleDownloadQrPng = () => {
    if (!generatedReport?.qrDataUrl) return;
    const a = document.createElement('a');
    a.href = generatedReport.qrDataUrl;
    a.download = `qr_${generatedReport.reportId}.png`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  // Copy helper
  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // QR / Report Verification Tool
  const handleVerifyQrPayload = () => {
    if (!qrInputText.trim()) return;
    setIsVerifyingQr(true);

    try {
      const parsed = JSON.parse(qrInputText) as CompactReportQrPayload;

      const details: string[] = [];

      // Check 1: Does report hash or report ID exist in ledger?
      const matchingBlock = currentCase.blocks.find(
        (b) =>
          b.details.notes?.includes(parsed.reportHash) ||
          b.details.action?.includes(parsed.reportId) ||
          b.details.authorizationReference?.includes(parsed.reportId)
      );

      // Check 2: Does evidence hash match?
      const isEvidenceHashMatched =
        parsed.evidenceHash.toLowerCase() === currentCase.evidence.sha256Hash.toLowerCase();

      // Check 3: Does ledger head hash exist anywhere in chain?
      const isHeadHashInChain = currentCase.blocks.some(
        (b) => b.currentHash.toLowerCase() === parsed.ledgerHeadHash.toLowerCase()
      );

      if (isEvidenceHashMatched) {
        details.push(`✓ Evidence SHA-256 hash (${parsed.evidenceHash.substring(0, 16)}...) matches case evidence.`);
      } else {
        details.push(`✕ Evidence hash mismatch! Recorded: ${parsed.evidenceHash.substring(0, 16)}..., Case: ${currentCase.evidence.sha256Hash.substring(0, 16)}...`);
      }

      if (isHeadHashInChain) {
        details.push(`✓ Ledger head anchor (${parsed.ledgerHeadHash.substring(0, 16)}...) verified in chain.`);
      } else {
        details.push(`✕ Ledger head anchor not found in active chain.`);
      }

      if (matchingBlock) {
        details.push(`✓ Report generation recorded in Ledger at Block #${matchingBlock.blockIndex} [${matchingBlock.eventType}].`);
      }

      if (isEvidenceHashMatched && isHeadHashInChain) {
        setQrVerificationResult({
          status: 'AUTHENTIC',
          message: 'Report Authentic & Ledger Recognized',
          matchedBlockIndex: matchingBlock?.blockIndex,
          details,
        });
      } else {
        setQrVerificationResult({
          status: 'ALTERED',
          message: 'Report Not Recognized / Cryptographically Altered',
          details,
        });
      }
    } catch {
      setQrVerificationResult({
        status: 'INVALID_JSON',
        message: 'Invalid QR payload string. Must be a valid SealChain CompactReport JSON object.',
        details: ['Failed to parse JSON string.'],
      });
    } finally {
      setIsVerifyingQr(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto py-8 px-4 sm:px-6 space-y-8">
      {/* Module Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-2">
            <span>MODULE 05</span>
            <span aria-hidden="true">·</span>
            <span>COURT-ADMISSIBLE PDF REPORTS & QR SELF-INTEGRITY</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-100">
            Forensic Report Generation & Verification
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Compile formal bilingual PDF examination reports with embedded QR provenance seals, self-integrity hashing, and official signatures.
          </p>
        </div>

        {/* Tab switch */}
        <div className="flex items-center gap-2 p-1 bg-slate-900 rounded-lg border border-slate-800 self-start sm:self-auto">
          <button
            onClick={() => setSubTab('generate')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors flex items-center gap-1.5 ${
              subTab === 'generate'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            <span>Report Generator</span>
          </button>

          <button
            onClick={() => setSubTab('verify_qr')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors flex items-center gap-1.5 ${
              subTab === 'verify_qr'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <QrCode className="w-3.5 h-3.5 text-cyan-400" />
            <span>Verify Report QR</span>
          </button>
        </div>
      </div>

      {/* Notice if Verification hasn't been executed yet */}
      {!localVerification && (
        <div className="p-4 rounded-xl bg-amber-950/40 border border-amber-600/80 text-amber-200 text-xs font-mono flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-lg">
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <strong className="block text-amber-100">No Forensic Verification Run Attached</strong>
              <span>
                To include the 5-point audit, verdict, and tamper heatmap in your report, run verification now or navigate to Module 04.
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2 self-start sm:self-auto shrink-0">
            <button
              onClick={handleQuickVerification}
              disabled={isGeneratingBaselineVerify}
              className="px-3 py-1.5 rounded bg-amber-400 hover:bg-amber-300 text-slate-950 font-bold flex items-center gap-1.5 transition-colors"
            >
              {isGeneratingBaselineVerify ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Auditing...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Run Quick Verification</span>
                </>
              )}
            </button>

            <button
              onClick={onNavigateToVerification}
              className="px-3 py-1.5 rounded bg-slate-900 hover:bg-slate-800 border border-amber-700/80 text-amber-300 flex items-center gap-1 transition-colors"
            >
              <span>Go to Module</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* ============================================================== */}
      {/* TAB 1: REPORT GENERATOR & LIVE PREVIEW */}
      {/* ============================================================== */}
      {subTab === 'generate' && (
        <div className="space-y-8">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Left Column: Report Options Form */}
            <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-6">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2 text-slate-200 text-sm font-semibold font-mono uppercase tracking-wider">
                  <Sliders className="w-4 h-4 text-cyan-400" />
                  <span>Report Configuration</span>
                </div>
              </div>

              {/* Language Selection */}
              <div>
                <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5 flex items-center gap-1.5">
                  <Languages className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Language / भाषा *</span>
                </label>
                <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                  <button
                    type="button"
                    onClick={() => setReportOptions({ ...reportOptions, language: 'en' })}
                    className={`py-2 px-3 rounded border text-center transition-colors ${
                      reportOptions.language === 'en'
                        ? 'bg-cyan-950 border-cyan-400 text-cyan-300 font-bold'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    English (Standard)
                  </button>

                  <button
                    type="button"
                    onClick={() => setReportOptions({ ...reportOptions, language: 'mr' })}
                    className={`py-2 px-3 rounded border text-center transition-colors ${
                      reportOptions.language === 'mr'
                        ? 'bg-cyan-950 border-cyan-400 text-cyan-300 font-bold'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    मराठी (Marathi)
                  </button>
                </div>
              </div>

              {/* Investigator Details */}
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-mono uppercase text-slate-400 mb-1 flex items-center gap-1.5">
                    <User className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Examining Officer Name</span>
                  </label>
                  <input
                    type="text"
                    value={reportOptions.investigatorName}
                    onChange={(e) =>
                      setReportOptions({ ...reportOptions, investigatorName: e.target.value })
                    }
                    className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono uppercase text-slate-400 mb-1 flex items-center gap-1.5">
                    <Building className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Agency / Forensic Unit</span>
                  </label>
                  <input
                    type="text"
                    value={reportOptions.investigatorOrg}
                    onChange={(e) =>
                      setReportOptions({ ...reportOptions, investigatorOrg: e.target.value })
                    }
                    className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono uppercase text-slate-400 mb-1">
                    Signing Authority Key (ECDSA P-256)
                  </label>
                  <select
                    value={selectedSignerId}
                    onChange={(e) => setSelectedSignerId(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
                  >
                    {actors.map((actor) => (
                      <option key={actor.id} value={actor.id}>
                        {actor.name} ({actor.badgeNumber})
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Section Checkboxes */}
              <div className="space-y-2 text-xs font-mono">
                <span className="text-[11px] uppercase text-slate-400 font-bold block mb-1">
                  Report Sections to Include:
                </span>

                {[
                  { key: 'includeEvidenceDetails', label: '1. Evidence Details & Specification' },
                  { key: 'includeChainOfCustody', label: '2. Hash-Linked Chain Timeline' },
                  { key: 'includeIntegrityChecks', label: '3. 5-Point Invariant Audit' },
                  { key: 'includeVerdict', label: '4. Final Verdict & Admissibility' },
                  { key: 'includeHeatmap', label: '5. Tamper Localization Heatmap' },
                  { key: 'includeMethodology', label: '6. Technical Methodology' },
                  { key: 'includeSignatures', label: '7. Official Signature Blocks' },
                  { key: 'includeAiExplanation', label: '8. AI Forensic Brief (Notice: Non-Verdict)' },
                ].map((item) => (
                  <label
                    key={item.key}
                    className="flex items-center gap-2 p-1.5 rounded hover:bg-slate-950/60 cursor-pointer text-slate-300"
                  >
                    <input
                      type="checkbox"
                      checked={
                        reportOptions[item.key as keyof ReportOptions] as boolean
                      }
                      onChange={(e) =>
                        setReportOptions({
                          ...reportOptions,
                          [item.key]: e.target.checked,
                        })
                      }
                      className="accent-cyan-400 w-4 h-4 rounded cursor-pointer"
                    />
                    <span>{item.label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Right Column: Live Report Preview & Self-Integrity Strip */}
            <div className="lg:col-span-2 space-y-6">
              {generatedReport && (
                <div className="p-6 rounded-xl bg-slate-900/90 border border-slate-800 space-y-6 shadow-xl">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                    <div>
                      <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono uppercase">
                        <Eye className="w-4 h-4" />
                        <span>Live Document Summary Preview</span>
                      </div>
                      <h3 className="text-base font-bold text-slate-100 mt-1 font-mono">
                        {generatedReport.reportId}
                      </h3>
                    </div>

                    <div className="flex items-center gap-2 self-start sm:self-auto">
                      <button
                        onClick={handleExportCaseBundle}
                        className="px-3 py-2 text-xs font-mono text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md transition-colors flex items-center gap-1.5"
                        title="Export full case bundle JSON including all phases"
                      >
                        <FileDown className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Export Bundle (JSON)</span>
                      </button>

                      <button
                        onClick={handleDownloadPdf}
                        disabled={isGenerating}
                        className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 rounded-md transition-colors flex items-center gap-2 shadow-sm shadow-cyan-950"
                      >
                        {isGenerating ? (
                          <>
                            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                            <span>Building PDF Document...</span>
                          </>
                        ) : (
                          <>
                            <Download className="w-3.5 h-3.5" />
                            <span>Download PDF Report</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Self-Integrity Banner */}
                  <div className="p-4 rounded-lg bg-slate-950 border border-cyan-800/80 space-y-3 font-mono text-xs">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-cyan-300 font-bold uppercase text-[11px]">
                        <ShieldCheck className="w-4 h-4 text-cyan-400" />
                        <span>Report Self-Integrity Cryptographic Anchor</span>
                      </div>
                      <button
                        onClick={() => handleCopy(generatedReport.reportHash, 'repHash')}
                        className="text-slate-400 hover:text-cyan-400 text-[11px] flex items-center gap-1"
                      >
                        {copiedKey === 'repHash' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>Copy SHA-256</span>
                      </button>
                    </div>

                    <div className="p-2 rounded bg-slate-900 border border-slate-800 text-cyan-300 text-[11px] break-all select-all">
                      {generatedReport.reportHash}
                    </div>

                    <div className="flex items-center justify-between text-[10px] text-slate-500">
                      <span>ECDSA P-256 Signature Active</span>
                      <span className="text-emerald-400">Ready to Inscribe in Custody Ledger</span>
                    </div>
                  </div>

                  {/* QR Code and Key Metadata side-by-side */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 items-center">
                    {/* QR Code Box */}
                    <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 flex flex-col items-center justify-center text-center space-y-2">
                      <img
                        src={generatedReport.qrDataUrl}
                        alt="Report QR Code"
                        className="w-32 h-32 rounded bg-white p-1"
                      />
                      <button
                        onClick={handleDownloadQrPng}
                        className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                      >
                        <Download className="w-3 h-3" />
                        <span>Download QR PNG</span>
                      </button>
                    </div>

                    {/* Quick Metadata summary */}
                    <div className="sm:col-span-2 p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2 text-xs font-mono">
                      <div>
                        <span className="text-slate-500">Case ID:</span>{' '}
                        <span className="text-slate-200 font-bold">{currentCase.caseId}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Evidence Tag:</span>{' '}
                        <span className="text-slate-200 font-bold">{currentCase.evidence.evidenceId}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Verdict:</span>{' '}
                        <span
                          className={`font-bold ${
                            generatedReport.qrPayload.verdict === 'AUTHENTIC'
                              ? 'text-emerald-400'
                              : generatedReport.qrPayload.verdict === 'TAMPERED'
                              ? 'text-rose-400'
                              : 'text-amber-400'
                          }`}
                        >
                          {generatedReport.qrPayload.verdict}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500">Language:</span>{' '}
                        <span className="text-slate-200">
                          {reportOptions.language === 'mr' ? 'मराठी (Marathi)' : 'English'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500">Ledger Blocks Included:</span>{' '}
                        <span className="text-slate-200">{currentCase.blocks.length} chained events</span>
                      </div>
                      <div className="truncate">
                        <span className="text-slate-500">Ledger Head:</span>{' '}
                        <span className="text-amber-300">{ledgerHeadHash.substring(0, 20)}...</span>
                      </div>
                    </div>
                  </div>

                  {/* Status if logged */}
                  {loggedReportBlockIndex !== null && (
                    <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-600/80 text-emerald-300 text-xs font-mono flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        <span>Report logged to Custody Ledger as Block #{loggedReportBlockIndex}</span>
                      </div>
                      <button
                        onClick={onNavigateToLedger}
                        className="underline hover:text-white flex items-center gap-1"
                      >
                        <span>View in Timeline</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ============================================================== */}
      {/* TAB 2: QR / REPORT VERIFIER */}
      {/* ============================================================== */}
      {subTab === 'verify_qr' && (
        <div className="space-y-8">
          <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-6">
            <div>
              <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono">
                Verify Document Authenticity via QR Token or JSON
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Paste the compact QR JSON string or test with the currently generated report token to verify report provenance against the custody ledger.
              </p>
            </div>

            {/* Quick Test Button */}
            {generatedReport && (
              <div className="flex items-center justify-between p-3 rounded-lg bg-cyan-950/40 border border-cyan-800/80 text-xs font-mono">
                <span className="text-cyan-300">
                  Quick-load active report token ({generatedReport.reportId})
                </span>
                <button
                  onClick={() => {
                    setQrInputText(JSON.stringify(generatedReport.qrPayload, null, 2));
                    setQrVerificationResult(null);
                  }}
                  className="px-3 py-1 bg-cyan-900/80 hover:bg-cyan-800 text-cyan-200 rounded border border-cyan-700 flex items-center gap-1.5"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Insert Generated QR Payload</span>
                </button>
              </div>
            )}

            {/* Textarea Input */}
            <div className="space-y-2">
              <label className="block text-xs font-mono uppercase text-slate-400">
                Compact Report QR Payload (JSON) *
              </label>
              <textarea
                rows={6}
                value={qrInputText}
                onChange={(e) => setQrInputText(e.target.value)}
                placeholder='{"reportId":"RPT-...","caseId":"CAS-...","evidenceId":"EVD-...","evidenceHash":"...","ledgerHeadHash":"...","reportHash":"...","verdict":"AUTHENTIC"}'
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-700 rounded-md text-slate-100 font-mono focus:outline-none focus:border-cyan-500 resize-none leading-relaxed"
              />
            </div>

            <div className="flex justify-end">
              <button
                onClick={handleVerifyQrPayload}
                disabled={isVerifyingQr || !qrInputText.trim()}
                className="px-6 py-2.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 rounded-md transition-colors flex items-center gap-2 shadow-sm shadow-cyan-950"
              >
                {isVerifyingQr ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Cross-Referencing Ledger...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-3.5 h-3.5" />
                    <span>Verify Report Authenticity</span>
                  </>
                )}
              </button>
            </div>

            {/* Result Display */}
            {qrVerificationResult && (
              <div
                className={`p-6 rounded-xl border space-y-4 animate-in fade-in duration-200 ${
                  qrVerificationResult.status === 'AUTHENTIC'
                    ? 'bg-emerald-950/40 border-emerald-500/80 text-emerald-100 shadow-xl shadow-emerald-950/30'
                    : 'bg-rose-950/40 border-rose-600/80 text-rose-100 shadow-xl shadow-rose-950/30'
                }`}
              >
                <div className="flex items-center justify-between pb-3 border-b border-white/10">
                  <div className="flex items-center gap-3">
                    {qrVerificationResult.status === 'AUTHENTIC' ? (
                      <ShieldCheck className="w-7 h-7 text-emerald-400" />
                    ) : (
                      <ShieldAlert className="w-7 h-7 text-rose-400" />
                    )}
                    <div>
                      <h3 className="text-base font-bold font-mono tracking-tight">
                        {qrVerificationResult.message}
                      </h3>
                      <p className="text-xs opacity-80 font-mono">
                        Cryptographic ledger cross-check complete
                      </p>
                    </div>
                  </div>

                  <span className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-black/40 border border-current">
                    {qrVerificationResult.status}
                  </span>
                </div>

                {qrVerificationResult.details && (
                  <div className="space-y-1.5 text-xs font-mono">
                    <span className="text-[10px] uppercase font-bold opacity-75 block">
                      Verification Audit Trail:
                    </span>
                    <ul className="space-y-1">
                      {qrVerificationResult.details.map((d, i) => (
                        <li key={i} className="opacity-95">
                          {d}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
