/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Sliders,
  Cpu,
  Layers,
  Sparkles,
  Download,
  Upload,
  RefreshCw,
  Eye,
  Info,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  HelpCircle,
  Activity,
  Play,
  RotateCcw,
  Zap,
} from 'lucide-react';
import {
  ForensicCase,
  ActorIdentity,
  CustodyBlock,
  WatermarkQualityMetrics,
  AttackResult,
  WatermarkExtractionResult,
} from '../types/forensics';
import {
  deriveWatermarkId,
  embedDCTWatermark,
  extractDCTWatermark,
  runRobustnessAttacks,
  applyVisibleWatermark,
} from '../crypto/dctWatermark';
import { loadImageDataFromUrl, imageDataToPngDataUrl } from '../crypto/stegoCrypto';
import { createSignedBlock } from '../crypto/webCrypto';

interface WatermarkingModuleProps {
  currentCase: ForensicCase;
  actors: ActorIdentity[];
  onAddCustodyBlock: (newBlock: CustodyBlock) => void;
  onNavigateToLedger: () => void;
}

export const WatermarkingModule: React.FC<WatermarkingModuleProps> = ({
  currentCase,
  actors,
  onAddCustodyBlock,
  onNavigateToLedger,
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'invisible' | 'attacks' | 'extract' | 'visible'>('invisible');

  // --- INVISIBLE WATERMARK STATE ---
  const [watermarkStrength, setWatermarkStrength] = useState<number>(25);
  const [watermarkIdHex, setWatermarkIdHex] = useState<string>('');
  const [watermarkBits, setWatermarkBits] = useState<number[]>([]);
  const [isEmbedding, setIsEmbedding] = useState<boolean>(false);
  const [embedProgress, setEmbedProgress] = useState<number>(0);
  const [watermarkedPngUrl, setWatermarkedPngUrl] = useState<string | null>(null);
  const [watermarkedImageData, setWatermarkedImageData] = useState<ImageData | null>(null);
  const [diffPngUrl, setDiffPngUrl] = useState<string | null>(null);
  const [qualityMetrics, setQualityMetrics] = useState<WatermarkQualityMetrics | null>(null);
  const [loggedBlockIndex, setLoggedBlockIndex] = useState<number | null>(null);
  const [embedError, setEmbedError] = useState<string | null>(null);

  // --- ATTACK LAB STATE ---
  const [isRunningAttacks, setIsRunningAttacks] = useState<boolean>(false);
  const [attackProgress, setAttackProgress] = useState<{ current: number; total: number; name: string } | null>(null);
  const [attackResults, setAttackResults] = useState<AttackResult[] | null>(null);

  // --- EXTRACTION STATE ---
  const extractInputRef = useRef<HTMLInputElement>(null);
  const [extractImageSrc, setExtractImageSrc] = useState<string | null>(null);
  const [extractFileName, setExtractFileName] = useState<string>('');
  const [isExtracting, setIsExtracting] = useState<boolean>(false);
  const [extractionResult, setExtractionResult] = useState<WatermarkExtractionResult | null>(null);

  // --- VISIBLE WATERMARK STATE ---
  const [visiblePos, setVisiblePos] = useState<'top-left' | 'top-right' | 'bottom-left' | 'bottom-right' | 'center' | 'tiled'>('bottom-right');
  const [visibleOpacity, setVisibleOpacity] = useState<number>(0.65);
  const [visibleFontSize, setVisibleFontSize] = useState<number>(18);
  const [visibleColor, setVisibleColor] = useState<string>('#38bdf8');
  const [visibleCustomText, setVisibleCustomText] = useState<string>('CHAIN OF CUSTODY CERTIFIED');
  const [visiblePreviewUrl, setVisiblePreviewUrl] = useState<string | null>(null);
  const [isGeneratingVisible, setIsGeneratingVisible] = useState<boolean>(false);

  // Educational drawer
  const [showEduGuide, setShowEduGuide] = useState<boolean>(false);

  // Compute 64-bit watermark ID derived from caseId and evidenceId
  useEffect(() => {
    async function initWatermarkId() {
      const derived = await deriveWatermarkId(currentCase.caseId, currentCase.evidence.evidenceId);
      setWatermarkIdHex(derived.hex);
      setWatermarkBits(derived.bits);
    }
    initWatermarkId();
  }, [currentCase.caseId, currentCase.evidence.evidenceId]);

  // Update visible watermark preview when controls change
  const updateVisiblePreview = useCallback(async () => {
    setIsGeneratingVisible(true);
    try {
      const url = await applyVisibleWatermark(currentCase.evidence.imageDataUrl, {
        caseId: currentCase.caseId,
        evidenceId: currentCase.evidence.evidenceId,
        timestamp: currentCase.evidence.timestamp.substring(0, 19).replace('T', ' '),
        customText: visibleCustomText,
        position: visiblePos,
        opacity: visibleOpacity,
        fontSize: visibleFontSize,
        color: visibleColor,
      });
      setVisiblePreviewUrl(url);
    } catch (err) {
      console.error('Visible watermark generation error:', err);
    } finally {
      setIsGeneratingVisible(false);
    }
  }, [currentCase.caseId, currentCase.evidence.evidenceId, currentCase.evidence.imageDataUrl, currentCase.evidence.timestamp, visibleColor, visibleCustomText, visibleFontSize, visibleOpacity, visiblePos]);

  useEffect(() => {
    if (activeSubTab === 'visible') {
      updateVisiblePreview();
    }
  }, [activeSubTab, updateVisiblePreview]);

  // --- EXECUTE 2D-DCT WATERMARK EMBEDDING ---
  const handleEmbedDCT = async () => {
    if (!watermarkBits.length) return;
    setIsEmbedding(true);
    setEmbedProgress(0);
    setEmbedError(null);

    try {
      // 1. Load original image as raw ImageData
      const { imageData } = await loadImageDataFromUrl(currentCase.evidence.imageDataUrl);

      // 2. Perform chunked 2D-DCT embedding in Y channel with mid-frequency pair
      const result = await embedDCTWatermark(
        imageData,
        watermarkBits,
        watermarkStrength,
        (percent) => setEmbedProgress(percent)
      );

      const watermarkedPng = imageDataToPngDataUrl(result.watermarkedImageData);
      const diffPng = imageDataToPngDataUrl(result.diffImageData);

      setWatermarkedPngUrl(watermarkedPng);
      setWatermarkedImageData(result.watermarkedImageData);
      setDiffPngUrl(diffPng);
      setQualityMetrics(result.metrics);

      // 3. Automatically add "WATERMARKED" event block to the custody ledger
      const signingActor = actors[0];
      const headBlock = currentCase.blocks[currentCase.blocks.length - 1];
      const prevHash = headBlock ? headBlock.currentHash : '0000000000000000000000000000000000000000000000000000000000000000';
      const nextIndex = currentCase.blocks.length;

      const watermarkedBlock = await createSignedBlock({
        blockIndex: nextIndex,
        previousHash: prevHash,
        eventType: 'WATERMARKED',
        actor: signingActor,
        details: {
          action: 'Robust 2D-DCT Frequency-Domain Watermarking (Y Channel)',
          departmentOrAgency: signingActor.agency,
          facilityLocation: 'Digital Forensics Watermarking & Authentication Suite',
          toolOrMethodUsed: `SealChain DCT Engine (8x8 Block 2D-DCT, Coeff Pair (4,3)/(3,4), Strength: ${watermarkStrength})`,
          notes: `Embedded 64-bit robust watermark ID [${watermarkIdHex}]. Quality: PSNR ${result.metrics.psnr} dB, SSIM ${result.metrics.ssim}. Redundant majority voting enabled for compression survival.`,
          authorizationReference: `Watermark Certificate #${currentCase.evidence.evidenceId}-DCT`,
        },
        evidenceId: currentCase.evidence.evidenceId,
        evidenceHash: currentCase.evidence.sha256Hash,
      });

      onAddCustodyBlock(watermarkedBlock);
      setLoggedBlockIndex(nextIndex);
    } catch (err: unknown) {
      console.error('DCT embedding error:', err);
      const msg = err instanceof Error ? err.message : 'Unknown DCT embedding error';
      setEmbedError(msg);
    } finally {
      setIsEmbedding(false);
    }
  };

  // Run Robustness Attack Lab
  const handleRunAttacks = async () => {
    if (!watermarkedImageData) return;
    setIsRunningAttacks(true);
    setAttackProgress({ current: 0, total: 7, name: 'Starting attacks...' });

    try {
      const results = await runRobustnessAttacks(
        watermarkedImageData,
        watermarkBits,
        watermarkIdHex,
        (current, total, name) => {
          setAttackProgress({ current, total, name });
        }
      );
      setAttackResults(results);
    } catch (err) {
      console.error('Attack execution error:', err);
    } finally {
      setIsRunningAttacks(false);
      setAttackProgress(null);
    }
  };

  // Execute extraction on uploaded or selected image
  const handleExtract = async () => {
    if (!extractImageSrc) return;
    setIsExtracting(true);
    setExtractionResult(null);

    try {
      const { imageData } = await loadImageDataFromUrl(extractImageSrc);
      const result = await extractDCTWatermark(imageData, watermarkBits, watermarkIdHex);
      setExtractionResult(result);
    } catch (err: unknown) {
      console.error('Extraction error:', err);
      const msg = err instanceof Error ? err.message : 'Extraction error';
      setExtractionResult({
        status: 'NOT_FOUND',
        extractedHex: '----------------',
        expectedHex: watermarkIdHex,
        matchedBits: 0,
        totalBits: 64,
        bitMatchPercent: 0,
        confidenceScore: 0,
        details: `Extraction failed: ${msg}`,
      });
    } finally {
      setIsExtracting(false);
    }
  };

  // Download helpers
  const handleDownloadInvisible = () => {
    if (!watermarkedPngUrl) return;
    const a = document.createElement('a');
    a.href = watermarkedPngUrl;
    a.download = `dct_watermarked_${currentCase.caseId}_${currentCase.evidence.evidenceId}.png`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const handleDownloadVisible = () => {
    if (!visiblePreviewUrl) return;
    const a = document.createElement('a');
    a.href = visiblePreviewUrl;
    a.download = `visible_watermarked_${currentCase.caseId}_${currentCase.evidence.evidenceId}.png`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  return (
    <div className="max-w-6xl mx-auto py-8 px-4 sm:px-6 space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-2">
            <span>MODULE 03</span>
            <span aria-hidden="true">·</span>
            <span>2D-DCT FREQUENCY DOMAIN & FORENSIC WATERMARKING</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-100">
            Cryptographic & Robust Watermarking
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Inscribe robust 2D-DCT watermark signatures that survive lossy compression, scaling, and noise, alongside visible custody overlays.
          </p>
        </div>

        <button
          onClick={() => setShowEduGuide(!showEduGuide)}
          className="px-3 py-1.5 text-xs font-mono text-cyan-300 hover:text-cyan-200 bg-cyan-950/60 border border-cyan-800 rounded flex items-center gap-1.5 self-start sm:self-auto transition-colors"
        >
          <HelpCircle className="w-3.5 h-3.5 text-cyan-400" />
          <span>{showEduGuide ? 'Hide Science Notes' : 'How DCT & SSIM Work'}</span>
        </button>
      </div>

      {/* Educational Guide Drawer */}
      {showEduGuide && (
        <div className="p-5 rounded-xl bg-slate-900/90 border border-cyan-900/60 text-xs space-y-4 animate-in fade-in duration-200">
          <div className="flex items-center gap-2 text-cyan-400 font-semibold font-mono uppercase">
            <Info className="w-4 h-4" />
            <span>Digital Watermarking & Signal Processing Foundations</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-slate-300 leading-relaxed">
            <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
              <strong className="text-cyan-300 block font-mono">1. 2D Discrete Cosine Transform (DCT)</strong>
              <p className="text-slate-400">
                Transforms 8x8 spatial pixel grids into frequency components. Modifying mid-frequency pairs (4,3) and (3,4) survives JPEG compression quantization tables without creating visible distortion.
              </p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
              <strong className="text-emerald-300 block font-mono">2. Robust vs Fragile Watermarks</strong>
              <p className="text-slate-400">
                Fragile watermarks (like Phase 2 LSB) are designed to break on any edit to verify exact integrity. Robust DCT watermarks are designed to survive image degradation, lossy transmission, and resizing for permanent ownership proof.
              </p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
              <strong className="text-amber-300 block font-mono">3. PSNR vs SSIM (Perceptual Quality)</strong>
              <p className="text-slate-400">
                PSNR calculates raw pixel variance in decibels (&gt;40 dB is excellent). SSIM (Structural Similarity) models human vision by evaluating luminance, contrast, and structure (1.0 is identical).
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Module Navigation Tabs */}
      <div className="flex flex-wrap items-center gap-2 p-1 bg-slate-900 rounded-lg border border-slate-800 max-w-2xl">
        <button
          onClick={() => setActiveSubTab('invisible')}
          className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors flex items-center gap-1.5 ${
            activeSubTab === 'invisible'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Cpu className="w-3.5 h-3.5 text-cyan-400" />
          <span>Invisible Robust DCT</span>
        </button>

        <button
          onClick={() => setActiveSubTab('attacks')}
          className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors flex items-center gap-1.5 ${
            activeSubTab === 'attacks'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Activity className="w-3.5 h-3.5 text-amber-400" />
          <span>Robustness Attack Lab</span>
          {attackResults && (
            <span className="text-[10px] font-mono px-1 bg-amber-950 text-amber-300 rounded border border-amber-800">
              {attackResults.filter((r) => r.passed).length}/7
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveSubTab('extract')}
          className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors flex items-center gap-1.5 ${
            activeSubTab === 'extract'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Eye className="w-3.5 h-3.5 text-cyan-400" />
          <span>Extract & Detect</span>
        </button>

        <button
          onClick={() => setActiveSubTab('visible')}
          className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors flex items-center gap-1.5 ${
            activeSubTab === 'visible'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-3.5 h-3.5 text-cyan-400" />
          <span>Visible Overlay</span>
        </button>
      </div>

      {/* ============================================================== */}
      {/* 1. INVISIBLE ROBUST DCT WATERMARK */}
      {/* ============================================================== */}
      {activeSubTab === 'invisible' && (
        <div className="space-y-8">
          <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono">
                  2D-DCT Frequency Embedding Parameters
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Embeds 64-bit cryptographic identity into the Luminance (Y) channel across 8x8 DCT blocks with redundant voting.
                </p>
              </div>

              <div className="text-xs font-mono text-cyan-400 bg-slate-950 px-3 py-1.5 rounded border border-slate-800">
                Watermark ID: <strong className="text-slate-100">{watermarkIdHex}</strong> (64 bits)
              </div>
            </div>

            {/* Strength vs Invisibility Slider */}
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <label className="text-xs font-mono uppercase text-slate-300 block">
                    Modulation Strength ($\Delta$): <span className="text-cyan-400 font-bold">{watermarkStrength}</span>
                  </label>
                  <p className="text-[11px] text-slate-500 font-mono mt-0.5">
                    Controls coefficient delta: Higher = survives harsher JPEG compression; Lower = higher PSNR / invisibility.
                  </p>
                </div>
                <div className="text-right text-[11px] font-mono">
                  <span className={watermarkStrength < 20 ? 'text-emerald-400' : watermarkStrength < 40 ? 'text-cyan-400' : 'text-amber-400'}>
                    {watermarkStrength < 20 ? 'Ultra High Invisibility' : watermarkStrength < 40 ? 'Balanced Forensic Standard' : 'Aggressive Robustness'}
                  </span>
                </div>
              </div>

              <input
                type="range"
                min="10"
                max="60"
                step="5"
                value={watermarkStrength}
                onChange={(e) => setWatermarkStrength(Number(e.target.value))}
                className="w-full accent-cyan-400 bg-slate-800 cursor-pointer"
              />
              <div className="flex justify-between text-[10px] font-mono text-slate-500">
                <span>10 (Stealth / 55+ dB)</span>
                <span>25 (Forensic Standard)</span>
                <span>40 (High Compression Defense)</span>
                <span>60 (Extreme Survival)</span>
              </div>
            </div>

            {/* Error Message */}
            {embedError && (
              <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-700 text-rose-300 text-xs font-mono">
                {embedError}
              </div>
            )}

            {/* Action Bar */}
            <div className="flex items-center justify-between pt-2">
              <div className="text-xs text-slate-400 font-mono">
                Source: {currentCase.evidence.imageFileName} ({currentCase.evidence.evidenceId})
              </div>

              <button
                onClick={handleEmbedDCT}
                disabled={isEmbedding}
                className="px-6 py-2.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 rounded-md transition-colors flex items-center gap-2 shadow-lg shadow-cyan-950"
              >
                {isEmbedding ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Executing 2D-DCT & Inverse DCT ({embedProgress}%)...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-3.5 h-3.5" />
                    <span>Embed 2D-DCT Watermark & Log to Ledger</span>
                  </>
                )}
              </button>
            </div>

            {/* Progress Bar */}
            {isEmbedding && (
              <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden border border-slate-800">
                <div
                  className="bg-cyan-400 h-1.5 transition-all duration-150"
                  style={{ width: `${embedProgress}%` }}
                />
              </div>
            )}
          </div>

          {/* Results: Quality Metrics & Visual Proof */}
          {watermarkedPngUrl && qualityMetrics && (
            <div className="p-6 rounded-xl bg-slate-900/90 border border-cyan-800/80 space-y-6 shadow-xl animate-in fade-in duration-200">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
                <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm font-mono uppercase tracking-wider">
                  <CheckCircle2 className="w-5 h-5" />
                  <span>2D-DCT Inscription Complete: Quality Certified</span>
                </div>

                {loggedBlockIndex !== null && (
                  <button
                    onClick={onNavigateToLedger}
                    className="text-xs font-mono text-cyan-300 hover:text-white flex items-center gap-1.5 px-2.5 py-1 rounded bg-cyan-950/80 border border-cyan-700"
                  >
                    <span>Logged to Ledger as Block #{loggedBlockIndex}</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                )}
              </div>

              {/* Quality Metrics Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-slate-500 text-[10px] uppercase block">
                    PSNR (Luminance)
                  </span>
                  <div className="text-xl font-bold text-cyan-300">
                    {qualityMetrics.psnr} <span className="text-xs font-normal text-slate-400">dB</span>
                  </div>
                  <span className="text-[10px] text-emerald-400 block">
                    High Fidelity (&gt; 40 dB)
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-slate-500 text-[10px] uppercase block">
                    SSIM (Structural Index)
                  </span>
                  <div className="text-xl font-bold text-emerald-300">
                    {qualityMetrics.ssim}
                  </div>
                  <span className="text-[10px] text-emerald-400 block">
                    {qualityMetrics.ssim >= 0.98 ? 'Perceptually Identical' : 'High Perceptual Match'}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-slate-500 text-[10px] uppercase block">
                    Mean Squared Error (MSE)
                  </span>
                  <div className="text-xl font-bold text-slate-200">
                    {qualityMetrics.mse}
                  </div>
                  <span className="text-[10px] text-slate-400 block">
                    Delta: ±{qualityMetrics.strength}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-slate-500 text-[10px] uppercase block">
                    Algorithm & Target
                  </span>
                  <div className="text-base font-bold text-slate-200 truncate">
                    8x8 DCT (4,3)/(3,4)
                  </div>
                  <span className="text-[10px] text-cyan-400 block">
                    Y Channel Majority Vote
                  </span>
                </div>
              </div>

              {/* 3-Way Side-by-Side Comparison */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="space-y-2">
                  <span className="text-xs font-mono uppercase text-slate-400 block text-center">
                    Original Specimen
                  </span>
                  <div className="rounded-lg overflow-hidden bg-slate-950 border border-slate-800 aspect-video flex items-center justify-center p-2">
                    <img
                      src={currentCase.evidence.imageDataUrl}
                      alt="Original"
                      className="max-h-full max-w-full object-contain rounded"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <span className="text-xs font-mono uppercase text-cyan-400 block text-center font-semibold">
                    DCT-Watermarked PNG
                  </span>
                  <div className="rounded-lg overflow-hidden bg-slate-950 border border-cyan-700/60 aspect-video flex items-center justify-center p-2">
                    <img
                      src={watermarkedPngUrl}
                      alt="Watermarked"
                      className="max-h-full max-w-full object-contain rounded"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <span className="text-xs font-mono uppercase text-amber-400 block text-center font-semibold">
                    Amplified Diff Map (x30)
                  </span>
                  <div className="rounded-lg overflow-hidden bg-black border border-amber-800/60 aspect-video flex items-center justify-center p-2">
                    {diffPngUrl ? (
                      <img
                        src={diffPngUrl}
                        alt="Difference x30"
                        className="max-h-full max-w-full object-contain rounded"
                      />
                    ) : null}
                  </div>
                </div>
              </div>

              {/* Actions */}
              <div className="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-slate-800">
                <span className="text-xs font-mono text-slate-400">
                  Ready for forensic attack testing and courtroom provenance verification.
                </span>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      setActiveSubTab('attacks');
                      setTimeout(handleRunAttacks, 100);
                    }}
                    className="px-3.5 py-2 text-xs font-mono text-amber-300 bg-amber-950/70 hover:bg-amber-900/80 border border-amber-700/80 rounded-md transition-colors flex items-center gap-1.5"
                  >
                    <Activity className="w-3.5 h-3.5" />
                    <span>Send to Robustness Attack Lab</span>
                  </button>

                  <button
                    onClick={handleDownloadInvisible}
                    className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md transition-colors flex items-center gap-2 shadow-sm shadow-cyan-950"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download Watermarked Image (PNG)</span>
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ============================================================== */}
      {/* 2. ROBUSTNESS ATTACK LAB */}
      {/* ============================================================== */}
      {activeSubTab === 'attacks' && (
        <div className="space-y-8">
          <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono">
                  Forensic Robustness Attack Benchmark Lab
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Simulates real-world lossy compression, transmission noise, cropping, and downscaling attacks to measure watermark survivability.
                </p>
              </div>

              <button
                onClick={handleRunAttacks}
                disabled={!watermarkedImageData || isRunningAttacks}
                className="px-5 py-2 text-xs font-semibold text-slate-950 bg-amber-400 hover:bg-amber-300 disabled:opacity-50 rounded-md transition-colors flex items-center gap-2 shadow-sm shadow-amber-950 self-start sm:self-auto"
              >
                {isRunningAttacks ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Running Attacks ({attackProgress?.current}/{attackProgress?.total})...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5" />
                    <span>Execute All 7 Robustness Attacks</span>
                  </>
                )}
              </button>
            </div>

            {!watermarkedImageData && (
              <div className="p-4 rounded-lg bg-amber-950/30 border border-amber-800 text-amber-300 text-xs font-mono flex items-center gap-2">
                <Info className="w-4 h-4 shrink-0 text-amber-400" />
                <span>
                  Please embed a 2D-DCT watermark in the &quot;Invisible Robust DCT&quot; tab first before running attacks.
                </span>
              </div>
            )}

            {/* Attack Progress indicator */}
            {isRunningAttacks && attackProgress && (
              <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2 font-mono text-xs">
                <div className="flex items-center justify-between text-slate-300">
                  <span>Executing Attack {attackProgress.current} of {attackProgress.total}:</span>
                  <span className="text-amber-400 font-bold">{attackProgress.name}</span>
                </div>
                <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
                  <div
                    className="bg-amber-400 h-2 transition-all duration-200"
                    style={{ width: `${(attackProgress.current / attackProgress.total) * 100}%` }}
                  />
                </div>
              </div>
            )}

            {/* Attack Results Table & Survival Chart */}
            {attackResults && (
              <div className="space-y-6 pt-2">
                {/* Summary Banner */}
                <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-center text-amber-400 font-mono font-bold text-lg">
                      {attackResults.filter((r) => r.passed).length}/{attackResults.length}
                    </div>
                    <div>
                      <div className="text-xs font-mono uppercase text-slate-400">
                        Attack Survival Rate
                      </div>
                      <div className="text-sm font-semibold text-slate-100">
                        {((attackResults.filter((r) => r.passed).length / attackResults.length) * 100).toFixed(0)}% Survival (Benchmark Threshold: &ge; 75% bit match)
                      </div>
                    </div>
                  </div>

                  <div className="text-xs font-mono text-slate-400">
                    Target Watermark: <strong className="text-cyan-300">{watermarkIdHex}</strong>
                  </div>
                </div>

                {/* Survival Rate Visual Bar Chart */}
                <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
                  <span className="text-xs font-mono uppercase text-slate-400 block font-semibold">
                    Survival Rate by Attack Vector (Bit Match %)
                  </span>
                  <div className="space-y-2 font-mono text-xs">
                    {attackResults.map((res) => (
                      <div key={res.id} className="space-y-1">
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-slate-300">{res.name}</span>
                          <span className={res.passed ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                            {res.bitMatchPercent}% ({res.matchedBits}/64 bits) {res.passed ? '✓ PASS' : '✕ FAIL'}
                          </span>
                        </div>
                        <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
                          <div
                            className={`h-2 transition-all duration-300 ${
                              res.bitMatchPercent >= 85
                                ? 'bg-emerald-400'
                                : res.bitMatchPercent >= 75
                                ? 'bg-amber-400'
                                : 'bg-rose-500'
                            }`}
                            style={{ width: `${res.bitMatchPercent}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Detailed Attack Rows */}
                <div className="border border-slate-800 rounded-lg overflow-hidden">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase text-[10px]">
                      <tr>
                        <th className="py-2.5 px-3">Visual Specimen</th>
                        <th className="py-2.5 px-3">Attack Name</th>
                        <th className="py-2.5 px-3">Mechanism</th>
                        <th className="py-2.5 px-3 text-right">Bit Match</th>
                        <th className="py-2.5 px-3 text-center">Outcome</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/80 bg-slate-900/60">
                      {attackResults.map((r) => (
                        <tr key={r.id} className="hover:bg-slate-800/40 transition-colors">
                          <td className="py-2 px-3">
                            {r.thumbnailDataUrl && (
                              <img
                                src={r.thumbnailDataUrl}
                                alt={r.name}
                                className="w-16 h-10 object-cover rounded border border-slate-700"
                              />
                            )}
                          </td>
                          <td className="py-2 px-3 font-semibold text-slate-200">
                            {r.name}
                          </td>
                          <td className="py-2 px-3 text-slate-400 text-[11px]">
                            {r.description}
                          </td>
                          <td className="py-2 px-3 text-right">
                            <span className="text-slate-200 font-bold">{r.bitMatchPercent}%</span>
                            <span className="text-slate-500 text-[10px] block">
                              ({r.matchedBits}/{r.totalBits} bits)
                            </span>
                          </td>
                          <td className="py-2 px-3 text-center">
                            <span
                              className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold ${
                                r.passed
                                  ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800'
                                  : 'bg-rose-950/80 text-rose-300 border border-rose-800'
                              }`}
                            >
                              {r.passed ? 'SURVIVED' : 'DESTROYED'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ============================================================== */}
      {/* 3. EXTRACT & DETECT WATERMARK */}
      {/* ============================================================== */}
      {activeSubTab === 'extract' && (
        <div className="space-y-8">
          <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-6">
            <div>
              <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono">
                Extract & Detect 2D-DCT Watermark Signature
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Upload any candidate image or test against the current watermarked specimen to verify majority-vote coefficient parity.
              </p>
            </div>

            <input
              type="file"
              ref={extractInputRef}
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) {
                  const reader = new FileReader();
                  reader.onload = () => {
                    setExtractImageSrc(reader.result as string);
                    setExtractFileName(file.name);
                    setExtractionResult(null);
                  };
                  reader.readAsDataURL(file);
                }
              }}
              accept="image/*"
              className="hidden"
            />

            {/* Quick Test Button */}
            {watermarkedPngUrl && (
              <div className="flex items-center justify-between p-3 rounded-lg bg-cyan-950/40 border border-cyan-800/80 text-xs font-mono">
                <span className="text-cyan-300">
                  Ready to test newly watermarked specimen with strength &Delta;={watermarkStrength}
                </span>
                <button
                  onClick={() => {
                    setExtractImageSrc(watermarkedPngUrl);
                    setExtractFileName(`dct_watermarked_${currentCase.evidence.evidenceId}.png`);
                    setExtractionResult(null);
                  }}
                  className="px-3 py-1 bg-cyan-900/80 hover:bg-cyan-800 text-cyan-200 rounded border border-cyan-700 flex items-center gap-1.5"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Load Just-Watermarked Specimen</span>
                </button>
              </div>
            )}

            {!extractImageSrc ? (
              <div
                onClick={() => extractInputRef.current?.click()}
                className="border-2 border-dashed border-slate-700 hover:border-cyan-500/60 rounded-xl p-8 text-center cursor-pointer transition-colors bg-slate-950/40 hover:bg-slate-900/50"
              >
                <div className="w-12 h-12 rounded-full bg-slate-800 flex items-center justify-center mx-auto mb-3 text-slate-300">
                  <Upload className="w-6 h-6 text-cyan-400" />
                </div>
                <p className="text-sm font-medium text-slate-200">
                  Click to upload image candidate for watermark extraction
                </p>
                <p className="text-xs text-slate-500 mt-1 font-mono">
                  Supports PNG, JPEG, WEBP. Analyzes 8x8 DCT luminance blocks.
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-stretch">
                <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 flex flex-col justify-between">
                  <div className="flex items-center justify-between mb-2 text-xs font-mono text-slate-400">
                    <span>Target: {extractFileName}</span>
                    <button
                      onClick={() => extractInputRef.current?.click()}
                      className="text-cyan-400 hover:underline"
                    >
                      Change File
                    </button>
                  </div>
                  <div className="flex-1 flex items-center justify-center max-h-56 overflow-hidden rounded bg-black/40">
                    <img
                      src={extractImageSrc}
                      alt="Candidate"
                      className="max-h-52 w-auto object-contain rounded"
                    />
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 flex flex-col justify-between space-y-4">
                  <div className="space-y-2 text-xs font-mono">
                    <span className="text-slate-400 uppercase text-[11px] block">
                      Target Forensic Case Signatures:
                    </span>
                    <div className="p-2.5 rounded bg-slate-900 border border-slate-800 space-y-1 text-[11px]">
                      <div>
                        <span className="text-slate-500">Case ID:</span>{' '}
                        <span className="text-slate-200 font-bold">{currentCase.caseId}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Evidence Tag:</span>{' '}
                        <span className="text-slate-200 font-bold">{currentCase.evidence.evidenceId}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Expected Hex ID:</span>{' '}
                        <span className="text-cyan-400 font-bold">{watermarkIdHex}</span>
                      </div>
                    </div>
                  </div>

                  <button
                    onClick={handleExtract}
                    disabled={isExtracting}
                    className="w-full py-2.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 rounded-md transition-colors flex items-center justify-center gap-2 shadow-sm shadow-cyan-950"
                  >
                    {isExtracting ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Running 2D-DCT & Voting across all blocks...</span>
                      </>
                    ) : (
                      <>
                        <Eye className="w-3.5 h-3.5" />
                        <span>Extract & Detect Watermark</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            )}

            {/* Extraction Result Card */}
            {extractionResult && (
              <div
                className={`p-6 rounded-xl border space-y-4 animate-in fade-in duration-200 ${
                  extractionResult.status === 'DETECTED'
                    ? 'bg-emerald-950/40 border-emerald-500/70 text-emerald-200'
                    : extractionResult.status === 'WEAK'
                    ? 'bg-amber-950/40 border-amber-500/70 text-amber-200'
                    : 'bg-rose-950/40 border-rose-600/70 text-rose-200'
                }`}
              >
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <div className="flex items-center gap-2.5">
                    {extractionResult.status === 'DETECTED' ? (
                      <ShieldCheck className="w-6 h-6 text-emerald-400" />
                    ) : extractionResult.status === 'WEAK' ? (
                      <AlertTriangle className="w-6 h-6 text-amber-400" />
                    ) : (
                      <ShieldAlert className="w-6 h-6 text-rose-400" />
                    )}
                    <div>
                      <h3 className="text-sm font-bold font-mono uppercase tracking-wider">
                        {extractionResult.status === 'DETECTED'
                          ? 'Watermark Detected'
                          : extractionResult.status === 'WEAK'
                          ? 'Weak / Degraded Watermark Signal'
                          : 'Not Found'}
                      </h3>
                      <p className="text-xs opacity-90">{extractionResult.details}</p>
                    </div>
                  </div>

                  <span className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-black/40 border border-current">
                    {extractionResult.bitMatchPercent}% MATCH
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono text-slate-300">
                  <div className="p-3 rounded bg-slate-950/80 border border-slate-800 space-y-1">
                    <span className="text-slate-500 text-[10px] uppercase block">
                      Expected Watermark Hex ID:
                    </span>
                    <div className="text-cyan-300 font-bold text-sm tracking-wider">
                      {extractionResult.expectedHex}
                    </div>
                  </div>

                  <div className="p-3 rounded bg-slate-950/80 border border-slate-800 space-y-1">
                    <span className="text-slate-500 text-[10px] uppercase block">
                      Extracted Watermark Hex ID:
                    </span>
                    <div className="text-slate-100 font-bold text-sm tracking-wider">
                      {extractionResult.extractedHex}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ============================================================== */}
      {/* 4. VISIBLE OVERLAY WATERMARK */}
      {/* ============================================================== */}
      {activeSubTab === 'visible' && (
        <div className="space-y-8">
          <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-6">
            <div>
              <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono">
                Visible Forensic Watermark Overlay
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Render authoritative chain of custody markings, timestamps, and case identifiers directly onto the visible image layer.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Controls Column */}
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                    Overlay Position
                  </label>
                  <select
                    value={visiblePos}
                    onChange={(e) =>
                      setVisiblePos(
                        e.target.value as
                          | 'top-left'
                          | 'top-right'
                          | 'bottom-left'
                          | 'bottom-right'
                          | 'center'
                          | 'tiled'
                      )
                    }
                    className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
                  >
                    <option value="bottom-right">Bottom-Right Corner</option>
                    <option value="bottom-left">Bottom-Left Corner</option>
                    <option value="top-right">Top-Right Corner</option>
                    <option value="top-left">Top-Left Corner</option>
                    <option value="center">Center Stamp</option>
                    <option value="tiled">Tiled 45° Repeating Security Pattern</option>
                  </select>
                </div>

                <div>
                  <div className="flex justify-between text-xs font-mono text-slate-400 mb-1.5">
                    <span>Opacity: {(visibleOpacity * 100).toFixed(0)}%</span>
                  </div>
                  <input
                    type="range"
                    min="0.1"
                    max="1.0"
                    step="0.05"
                    value={visibleOpacity}
                    onChange={(e) => setVisibleOpacity(Number(e.target.value))}
                    className="w-full accent-cyan-400 bg-slate-800 cursor-pointer"
                  />
                </div>

                <div>
                  <div className="flex justify-between text-xs font-mono text-slate-400 mb-1.5">
                    <span>Font Size: {visibleFontSize}px</span>
                  </div>
                  <input
                    type="range"
                    min="12"
                    max="42"
                    step="2"
                    value={visibleFontSize}
                    onChange={(e) => setVisibleFontSize(Number(e.target.value))}
                    className="w-full accent-cyan-400 bg-slate-800 cursor-pointer"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                    Font Color
                  </label>
                  <div className="flex items-center gap-2">
                    {['#38bdf8', '#ffffff', '#fbbf24', '#f87171', '#0f172a'].map((c) => (
                      <button
                        key={c}
                        type="button"
                        onClick={() => setVisibleColor(c)}
                        className={`w-7 h-7 rounded border transition-transform ${
                          visibleColor === c ? 'scale-110 border-white ring-2 ring-cyan-500' : 'border-slate-700'
                        }`}
                        style={{ backgroundColor: c }}
                      />
                    ))}
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                    Custom Banner Text
                  </label>
                  <input
                    type="text"
                    value={visibleCustomText}
                    onChange={(e) => setVisibleCustomText(e.target.value)}
                    placeholder="e.g. EVIDENCE - DO NOT DISTRIBUTE"
                    className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <button
                  type="button"
                  onClick={handleDownloadVisible}
                  disabled={!visiblePreviewUrl}
                  className="w-full py-2.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md transition-colors flex items-center justify-center gap-2 shadow-sm shadow-cyan-950"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download Visible Watermarked Image (PNG)</span>
                </button>
              </div>

              {/* Live Preview Column */}
              <div className="md:col-span-2 space-y-2">
                <span className="text-xs font-mono uppercase text-slate-400 block">
                  Live Watermarked Specimen Canvas
                </span>
                <div className="rounded-xl overflow-hidden bg-slate-950 border border-slate-800 aspect-video flex items-center justify-center p-3 relative">
                  {isGeneratingVisible ? (
                    <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs">
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Compositing overlay...</span>
                    </div>
                  ) : visiblePreviewUrl ? (
                    <img
                      src={visiblePreviewUrl}
                      alt="Visible Preview"
                      className="max-h-full max-w-full object-contain rounded"
                    />
                  ) : null}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
