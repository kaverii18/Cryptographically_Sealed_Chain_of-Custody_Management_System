/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Lock,
  Key,
  Eye,
  EyeOff,
  Download,
  Upload,
  RefreshCw,
  FileCode,
  Info,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Sparkles,
  Layers,
  HelpCircle,
} from 'lucide-react';
import {
  ForensicCase,
  ActorIdentity,
  CustodyBlock,
  StegoPayload,
  StegoExtractionResult,
  InvisibilityMetrics,
} from '../types/forensics';
import {
  createSignedStegoPayload,
  encryptPayloadAESGCM,
  decryptPayloadAESGCM,
  embedBytesLSB,
  extractBytesLSB,
  calculatePSNRAndDiff,
  calculateImageLSBCapacityBytes,
  loadImageDataFromUrl,
  imageDataToPngDataUrl,
  verifyStegoSignature,
} from '../crypto/stegoCrypto';
import { createSignedBlock } from '../crypto/webCrypto';

interface SteganographyModuleProps {
  currentCase: ForensicCase;
  actors: ActorIdentity[];
  onAddCustodyBlock: (newBlock: CustodyBlock) => void;
  onNavigateToLedger: () => void;
}

export const SteganographyModule: React.FC<SteganographyModuleProps> = ({
  currentCase,
  actors,
  onAddCustodyBlock,
  onNavigateToLedger,
}) => {
  const [subTab, setSubTab] = useState<'embed' | 'extract'>('embed');

  // --- EMBED STATE ---
  const [selectedActorId, setSelectedActorId] = useState<string>(actors[0]?.id || '');
  const [passphrase, setPassphrase] = useState<string>('ForensicSecure#2026');
  const [showPassphrase, setShowPassphrase] = useState<boolean>(false);
  const [stegoPayload, setStegoPayload] = useState<StegoPayload | null>(null);
  const [isGeneratingPayload, setIsGeneratingPayload] = useState<boolean>(false);

  // Embedding execution
  const [isEmbedding, setIsEmbedding] = useState<boolean>(false);
  const [sealedImageDataUrl, setSealedImageDataUrl] = useState<string | null>(null);
  const [diffImageDataUrl, setDiffImageDataUrl] = useState<string | null>(null);
  const [invisibilityMetrics, setInvisibilityMetrics] = useState<InvisibilityMetrics | null>(null);
  const [embedError, setEmbedError] = useState<string | null>(null);
  const [justLoggedBlockIndex, setJustLoggedBlockIndex] = useState<number | null>(null);

  // --- EXTRACT STATE ---
  const extractFileInputRef = useRef<HTMLInputElement>(null);
  const [extractImageSrc, setExtractImageSrc] = useState<string | null>(null);
  const [extractFileName, setExtractFileName] = useState<string>('');
  const [extractPassphrase, setExtractPassphrase] = useState<string>('ForensicSecure#2026');
  const [showExtractPassphrase, setShowExtractPassphrase] = useState<boolean>(false);
  const [isExtracting, setIsExtracting] = useState<boolean>(false);
  const [extractionResult, setExtractionResult] = useState<StegoExtractionResult | null>(null);

  // Educational accordion toggle
  const [showEduGuide, setShowEduGuide] = useState<boolean>(false);

  const headBlock = currentCase.blocks[currentCase.blocks.length - 1];
  const ledgerHeadHash = headBlock ? headBlock.currentHash : '0000000000000000000000000000000000000000000000000000000000000000';

  // 1. Auto-generate or update unsealed payload preview when actor or case changes
  useEffect(() => {
    let isCancelled = false;
    async function buildPayloadPreview() {
      const activeActor = actors.find((a) => a.id === selectedActorId) || actors[0];
      if (!activeActor || !currentCase) return;

      setIsGeneratingPayload(true);
      try {
        const payload = await createSignedStegoPayload({
          caseId: currentCase.caseId,
          evidenceId: currentCase.evidence.evidenceId,
          originalImageHash: currentCase.evidence.sha256Hash,
          ledgerHeadHash,
          actor: activeActor,
        });
        if (!isCancelled) {
          setStegoPayload(payload);
        }
      } catch (err) {
        console.error('Failed to create preview payload:', err);
      } finally {
        if (!isCancelled) setIsGeneratingPayload(false);
      }
    }

    buildPayloadPreview();
    return () => {
      isCancelled = true;
    };
  }, [selectedActorId, currentCase, ledgerHeadHash, actors]);

  // Handle Embed Steganography
  const handleEmbedSeal = async () => {
    if (!stegoPayload) return;
    if (!passphrase.trim()) {
      setEmbedError('Please provide an encryption passphrase for PBKDF2/AES-GCM.');
      return;
    }

    setEmbedError(null);
    setIsEmbedding(true);

    try {
      // 1. Load original image as raw ImageData
      const { imageData: origImageData, width, height } = await loadImageDataFromUrl(
        currentCase.evidence.imageDataUrl
      );

      // Capacity check
      const capacityBytes = calculateImageLSBCapacityBytes(width, height);

      // 2. Encrypt JSON payload with PBKDF2 (100k rounds) + AES-GCM
      const payloadJson = JSON.stringify(stegoPayload);
      const encryptedBytes = await encryptPayloadAESGCM(payloadJson, passphrase.trim());

      if (encryptedBytes.length > capacityBytes) {
        throw new Error(
          `Payload size (${encryptedBytes.length} bytes) exceeds image maximum LSB capacity (${capacityBytes} bytes).`
        );
      }

      // 3. Embed encrypted bytes into LSB of R, G, B channels
      const { sealedImageData } = embedBytesLSB(origImageData, encryptedBytes);

      // 4. Calculate visual proof of invisibility metrics (PSNR, MSE, x50 Diff Map)
      const { metrics, diffImageData } = calculatePSNRAndDiff(
        origImageData,
        sealedImageData,
        encryptedBytes.length
      );

      // 5. Convert to PNG Data URLs
      const sealedPngUrl = imageDataToPngDataUrl(sealedImageData);
      const diffPngUrl = imageDataToPngDataUrl(diffImageData);

      setSealedImageDataUrl(sealedPngUrl);
      setDiffImageDataUrl(diffPngUrl);
      setInvisibilityMetrics(metrics);

      // 6. Log "SEALED" event automatically to custody ledger
      const signingActor = actors.find((a) => a.id === selectedActorId) || actors[0];
      const nextBlockIndex = currentCase.blocks.length;

      const sealedBlock = await createSignedBlock({
        blockIndex: nextBlockIndex,
        previousHash: ledgerHeadHash,
        eventType: 'SEALED',
        actor: signingActor,
        details: {
          action: 'Cryptographic LSB Steganography Embedding (AES-256-GCM + PBKDF2)',
          departmentOrAgency: signingActor.agency,
          facilityLocation: 'Digital Forensics Watermarking & Steganography Lab',
          toolOrMethodUsed: `SealChain Stego Engine (LSB R/G/B, 100k PBKDF2 rounds, PSNR: ${metrics.psnr} dB)`,
          notes: `Cryptographically sealed evidence specimen with encrypted custody metadata. Embedded payload: Case ${currentCase.caseId}, Head ${ledgerHeadHash.substring(0, 16)}..., PSNR ${metrics.psnr} dB (${metrics.modifiedPixels} pixels modified).`,
          authorizationReference: `Stego Seal Record #${currentCase.evidence.evidenceId}-STEGO`,
        },
        evidenceId: currentCase.evidence.evidenceId,
        evidenceHash: currentCase.evidence.sha256Hash,
      });

      onAddCustodyBlock(sealedBlock);
      setJustLoggedBlockIndex(nextBlockIndex);
    } catch (err: unknown) {
      console.error('Embedding error:', err);
      const msg = err instanceof Error ? err.message : 'Unknown embedding error';
      setEmbedError(msg);
    } finally {
      setIsEmbedding(false);
    }
  };

  // Download sealed image as PNG
  const handleDownloadSealedImage = () => {
    if (!sealedImageDataUrl) return;
    const a = document.createElement('a');
    a.href = sealedImageDataUrl;
    a.download = `sealed_${currentCase.caseId}_${currentCase.evidence.evidenceId}.png`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  // Test extract on the newly sealed image directly
  const handleLoadJustSealed = () => {
    if (!sealedImageDataUrl) return;
    setExtractImageSrc(sealedImageDataUrl);
    setExtractFileName(`sealed_${currentCase.evidence.evidenceId}.png`);
    setExtractPassphrase(passphrase);
    setExtractionResult(null);
    setSubTab('extract');
  };

  // Handle image upload for extraction
  const handleExtractFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      if (!file.type.startsWith('image/')) {
        setExtractionResult({
          status: 'NO_SEAL_FOUND',
          payload: null,
          errorMessage: 'Uploaded file is not a supported image format.',
        });
        return;
      }

      const reader = new FileReader();
      reader.onload = () => {
        setExtractImageSrc(reader.result as string);
        setExtractFileName(file.name);
        setExtractionResult(null);
      };
      reader.readAsDataURL(file);
    }
  };

  // Execute extraction & verification
  const handleExtractSeal = async () => {
    if (!extractImageSrc) return;
    setIsExtracting(true);
    setExtractionResult(null);

    try {
      // 1. Load image onto canvas and read ImageData
      const { imageData } = await loadImageDataFromUrl(extractImageSrc);

      // 2. Extract embedded bytes from LSB
      const extractedBytes = extractBytesLSB(imageData);
      if (!extractedBytes) {
        setExtractionResult({
          status: 'NO_SEAL_FOUND',
          payload: null,
          errorMessage:
            'No cryptographic SealChain marker or valid LSB header was detected in this image.',
        });
        setIsExtracting(false);
        return;
      }

      // 3. Attempt decryption using provided passphrase
      let decryptedJson = '';
      try {
        decryptedJson = await decryptPayloadAESGCM(extractedBytes, extractPassphrase.trim());
      } catch (err: unknown) {
        setExtractionResult({
          status: 'WRONG_PASSPHRASE_OR_CORRUPT',
          payload: null,
          errorMessage:
            'Decryption failed. The passphrase was incorrect or the embedded ciphertext was corrupted/altered (AES-GCM authentication tag mismatch).',
        });
        setIsExtracting(false);
        return;
      }

      // 4. Parse decrypted payload
      const payload = JSON.parse(decryptedJson) as StegoPayload;

      // 5. Verify ECDSA signature
      const isSigValid = await verifyStegoSignature(payload);

      // 6. Verify ledger head hash exists in current case
      const matchingBlock = currentCase.blocks.find(
        (b) => b.currentHash.toLowerCase() === payload.ledgerHeadHash.toLowerCase()
      );
      const isHeadMatched = !!matchingBlock;
      const headDetails = matchingBlock
        ? `Matched Block #${matchingBlock.blockIndex} [${matchingBlock.eventType}] in active ledger.`
        : `Head hash (${payload.ledgerHeadHash.substring(0, 16)}...) was not found in the current active case ledger.`;

      setExtractionResult({
        status: isSigValid ? 'VALID' : 'WRONG_PASSPHRASE_OR_CORRUPT',
        payload,
        isSignatureValid: isSigValid,
        isLedgerHeadMatched: isHeadMatched,
        ledgerHeadMatchDetails: headDetails,
      });
    } catch (err: unknown) {
      console.error('Extraction error:', err);
      const msg = err instanceof Error ? err.message : 'Unknown extraction error';
      setExtractionResult({
        status: 'WRONG_PASSPHRASE_OR_CORRUPT',
        payload: null,
        errorMessage: `Extraction error: ${msg}`,
      });
    } finally {
      setIsExtracting(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto py-8 px-4 sm:px-6 space-y-8">
      {/* Module Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-2">
            <span>MODULE 02</span>
            <span aria-hidden="true">·</span>
            <span>LSB STEGANOGRAPHY & AUTHENTICATED ENCRYPTION</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-100">
            Cryptographic Steganographic Sealing
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Inscribe authenticated case custody proofs directly into the pixel matrix of evidence images using PBKDF2, AES-256-GCM, and lossless LSB embedding.
          </p>
        </div>

        {/* Educational Guide Toggle */}
        <button
          onClick={() => setShowEduGuide(!showEduGuide)}
          className="px-3 py-1.5 text-xs font-mono text-cyan-300 hover:text-cyan-200 bg-cyan-950/60 border border-cyan-800 rounded flex items-center gap-1.5 self-start sm:self-auto transition-colors"
        >
          <HelpCircle className="w-3.5 h-3.5 text-cyan-400" />
          <span>{showEduGuide ? 'Hide Lab Explainer' : 'How LSB & AES Work'}</span>
        </button>
      </div>

      {/* Educational Explainer Drawer */}
      {showEduGuide && (
        <div className="p-5 rounded-xl bg-slate-900/90 border border-cyan-900/60 text-xs space-y-4 animate-in fade-in duration-200">
          <div className="flex items-center gap-2 text-cyan-400 font-semibold font-mono uppercase">
            <Info className="w-4 h-4" />
            <span>Forensic Science Principles in SealChain</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-slate-300 leading-relaxed">
            <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
              <strong className="text-cyan-300 block font-mono">1. LSB Steganography</strong>
              <p className="text-slate-400">
                Each pixel has Red, Green, and Blue values from 0 to 255. Altering the Least Significant Bit (e.g. changing 210 to 211) modifies light intensity by less than 0.39%, mathematically invisible to the human visual system.
              </p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
              <strong className="text-emerald-300 block font-mono">2. PBKDF2 + AES-GCM</strong>
              <p className="text-slate-400">
                A user passphrase is key-stretched with 100,000 rounds of SHA-256 and a random 16-byte salt to prevent rainbow-table attacks. AES-GCM guarantees both confidentiality and tamper detection through its 128-bit authentication tag.
              </p>
            </div>
            <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
              <strong className="text-amber-300 block font-mono">3. PSNR Metric (Fidelity)</strong>
              <p className="text-slate-400">
                Peak Signal-to-Noise Ratio (PSNR) measures visual distortion. Values above 40 dB indicate that modifications cannot be distinguished by human vision. SealChain typically achieves over 60 dB.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Primary Module Tabs */}
      <div className="flex items-center gap-2 p-1 bg-slate-900 rounded-lg border border-slate-800 max-w-md">
        <button
          onClick={() => setSubTab('embed')}
          className={`flex-1 py-2 text-xs font-semibold rounded-md transition-colors flex items-center justify-center gap-2 ${
            subTab === 'embed'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-4 h-4 text-cyan-400" />
          <span>Embed Hidden Seal</span>
        </button>

        <button
          onClick={() => setSubTab('extract')}
          className={`flex-1 py-2 text-xs font-semibold rounded-md transition-colors flex items-center justify-center gap-2 ${
            subTab === 'extract'
              ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Key className="w-4 h-4 text-cyan-400" />
          <span>Extract & Authenticate</span>
        </button>
      </div>

      {/* ============================================================== */}
      {/* TAB 1: EMBED CRYPTOGRAPHIC SEAL */}
      {/* ============================================================== */}
      {subTab === 'embed' && (
        <div className="space-y-8">
          {/* Section 1: Configuration & Passphrase */}
          <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-slate-200 text-sm font-semibold font-mono uppercase tracking-wider">
                <Sliders className="w-4 h-4 text-cyan-400" />
                <span>1. Sealing Parameters & Key Derivation</span>
              </div>
              <span className="text-xs font-mono text-cyan-400">
                Head Hash: {ledgerHeadHash.substring(0, 16)}...
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Signing Actor */}
              <div>
                <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                  Signing Forensic Custodian *
                </label>
                <select
                  value={selectedActorId}
                  onChange={(e) => setSelectedActorId(e.target.value)}
                  className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
                >
                  {actors.map((actor) => (
                    <option key={actor.id} value={actor.id}>
                      {actor.name} — {actor.role} ({actor.agency})
                    </option>
                  ))}
                </select>
                <p className="text-[11px] text-slate-500 mt-1 font-mono">
                  Signs the seal payload with ECDSA P-256 before encryption.
                </p>
              </div>

              {/* Passphrase for PBKDF2 */}
              <div>
                <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                  Encryption Passphrase (PBKDF2-SHA256) *
                </label>
                <div className="relative">
                  <input
                    type={showPassphrase ? 'text' : 'password'}
                    value={passphrase}
                    onChange={(e) => setPassphrase(e.target.value)}
                    required
                    placeholder="Enter strong passphrase"
                    className="w-full px-3 py-2 pr-10 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassphrase(!showPassphrase)}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 p-1"
                  >
                    {showPassphrase ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                <p className="text-[11px] text-slate-500 mt-1 font-mono">
                  Generates a 256-bit AES-GCM key with 100,000 iterations & random 16-byte salt.
                </p>
              </div>
            </div>
          </div>

          {/* Section 2: Seal Payload Inspector (Before Embedding) */}
          <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-slate-200 text-sm font-semibold font-mono uppercase tracking-wider">
                <FileCode className="w-4 h-4 text-cyan-400" />
                <span>2. Unencrypted Seal Payload (ECDSA-Signed)</span>
              </div>
              <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/80 px-2 py-0.5 rounded">
                Pre-Embedding Signature Verified
              </span>
            </div>

            {isGeneratingPayload ? (
              <div className="p-6 text-center text-xs font-mono text-cyan-400 flex items-center justify-center gap-2">
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Computing Canonical Payload & Signing with ECDSA P-256...</span>
              </div>
            ) : stegoPayload ? (
              <div className="space-y-4">
                <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs space-y-2 overflow-x-auto text-slate-300">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                    <div>
                      <span className="text-slate-500">Case Identifier:</span>{' '}
                      <span className="text-cyan-300 font-semibold">{stegoPayload.caseId}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Evidence Tag:</span>{' '}
                      <span className="text-cyan-300 font-semibold">{stegoPayload.evidenceId}</span>
                    </div>
                    <div className="truncate">
                      <span className="text-slate-500">Original SHA-256:</span>{' '}
                      <span className="text-slate-300">{stegoPayload.originalImageHash.substring(0, 20)}...</span>
                    </div>
                    <div className="truncate">
                      <span className="text-slate-500">Ledger Head Hash:</span>{' '}
                      <span className="text-amber-300">{stegoPayload.ledgerHeadHash.substring(0, 20)}...</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Signer:</span>{' '}
                      <span className="text-slate-200">{stegoPayload.signerName} ({stegoPayload.signerRole})</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Timestamp:</span>{' '}
                      <span className="text-slate-400">{stegoPayload.timestamp}</span>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800 text-[11px] truncate">
                    <span className="text-emerald-400 font-semibold">ECDSA Signature:</span>{' '}
                    <span className="text-emerald-300/80">{stegoPayload.signatureHex.substring(0, 48)}...</span>
                  </div>
                </div>

                {embedError && (
                  <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-700 text-rose-300 text-xs font-mono flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
                    <span>{embedError}</span>
                  </div>
                )}

                <div className="flex items-center justify-between pt-2">
                  <div className="text-xs text-slate-400 font-mono">
                    Target: Evidence Specimen ({currentCase.evidence.imageFileName})
                  </div>

                  <button
                    onClick={handleEmbedSeal}
                    disabled={isEmbedding}
                    className="px-6 py-2.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 rounded-md transition-colors flex items-center gap-2 shadow-lg shadow-cyan-950"
                  >
                    {isEmbedding ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Deriving Keys & Embedding LSB Bits...</span>
                      </>
                    ) : (
                      <>
                        <Lock className="w-3.5 h-3.5" />
                        <span>Encrypt & Embed into Evidence (LSB)</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            ) : null}
          </div>

          {/* Section 3: Visual Proof of Invisibility & Telemetry (Visible after embedding) */}
          {sealedImageDataUrl && invisibilityMetrics && (
            <div className="p-6 rounded-xl bg-slate-900/90 border border-cyan-800/80 space-y-6 shadow-xl">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
                <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm font-mono uppercase tracking-wider">
                  <CheckCircle2 className="w-5 h-5" />
                  <span>3. Visual Proof of Invisibility & Quality Telemetry</span>
                </div>

                {justLoggedBlockIndex !== null && (
                  <button
                    onClick={onNavigateToLedger}
                    className="text-xs font-mono text-cyan-300 hover:text-white flex items-center gap-1.5 px-2.5 py-1 rounded bg-cyan-950/80 border border-cyan-700"
                  >
                    <span>Logged to Ledger as Block #{justLoggedBlockIndex}</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                )}
              </div>

              {/* Metrics Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-slate-500 text-[10px] uppercase block">
                    PSNR (Visual Fidelity)
                  </span>
                  <div className="text-xl font-bold text-cyan-300">
                    {invisibilityMetrics.psnr} <span className="text-xs font-normal text-slate-400">dB</span>
                  </div>
                  <span className="text-[10px] text-emerald-400 block">
                    Imperceptible (&gt; 40 dB standard)
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-slate-500 text-[10px] uppercase block">
                    Modified Pixels
                  </span>
                  <div className="text-xl font-bold text-slate-200">
                    {invisibilityMetrics.modifiedPixels.toLocaleString()}
                  </div>
                  <span className="text-[10px] text-slate-400 block">
                    {(
                      (invisibilityMetrics.modifiedPixels / invisibilityMetrics.totalPixels) *
                      100
                    ).toFixed(2)}
                    % of total pixels
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-slate-500 text-[10px] uppercase block">
                    Payload Size
                  </span>
                  <div className="text-xl font-bold text-slate-200">
                    {invisibilityMetrics.payloadSizeBytes.toLocaleString()}{' '}
                    <span className="text-xs font-normal text-slate-400">bytes</span>
                  </div>
                  <span className="text-[10px] text-slate-400 block">
                    {invisibilityMetrics.capacityPercentageUsed}% of capacity
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-slate-500 text-[10px] uppercase block">
                    Total Image Capacity
                  </span>
                  <div className="text-xl font-bold text-slate-200">
                    {(invisibilityMetrics.totalCapacityBytes / 1024).toFixed(1)}{' '}
                    <span className="text-xs font-normal text-slate-400">KB</span>
                  </div>
                  <span className="text-[10px] text-cyan-400 block">
                    R, G, B LSB Available
                  </span>
                </div>
              </div>

              {/* Side-by-Side Visual Comparison & Diff Map */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* 1. Original */}
                <div className="space-y-2">
                  <span className="text-xs font-mono uppercase text-slate-400 block text-center">
                    Original Specimen
                  </span>
                  <div className="rounded-lg overflow-hidden bg-slate-950 border border-slate-800 aspect-video flex items-center justify-center p-2">
                    <img
                      src={currentCase.evidence.imageDataUrl}
                      alt="Original Evidence"
                      className="max-h-full max-w-full object-contain rounded"
                    />
                  </div>
                </div>

                {/* 2. Sealed Image */}
                <div className="space-y-2">
                  <span className="text-xs font-mono uppercase text-cyan-400 block text-center font-semibold">
                    Steganographically Sealed PNG
                  </span>
                  <div className="rounded-lg overflow-hidden bg-slate-950 border border-cyan-700/60 aspect-video flex items-center justify-center p-2">
                    <img
                      src={sealedImageDataUrl}
                      alt="Sealed PNG"
                      className="max-h-full max-w-full object-contain rounded"
                    />
                  </div>
                </div>

                {/* 3. Amplified Diff Map (x50) */}
                <div className="space-y-2">
                  <span className="text-xs font-mono uppercase text-amber-400 block text-center font-semibold">
                    Amplified Diff Map (x50)
                  </span>
                  <div className="rounded-lg overflow-hidden bg-black border border-amber-800/60 aspect-video flex items-center justify-center p-2">
                    {diffImageDataUrl ? (
                      <img
                        src={diffImageDataUrl}
                        alt="Difference Map x50"
                        className="max-h-full max-w-full object-contain rounded"
                      />
                    ) : null}
                  </div>
                </div>
              </div>

              {/* Download & Actions */}
              <div className="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-slate-800">
                <span className="text-xs font-mono text-slate-400">
                  Export format: Lossless PNG (JPEG re-encoding would destroy LSB bits)
                </span>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleLoadJustSealed}
                    className="px-3.5 py-2 text-xs font-mono text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md transition-colors flex items-center gap-1.5"
                  >
                    <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Test Extracting This Image</span>
                  </button>

                  <button
                    onClick={handleDownloadSealedImage}
                    className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md transition-colors flex items-center gap-2 shadow-sm shadow-cyan-950"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download Sealed Image (PNG)</span>
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ============================================================== */}
      {/* TAB 2: EXTRACT & AUTHENTICATE SEAL */}
      {/* ============================================================== */}
      {subTab === 'extract' && (
        <div className="space-y-8">
          <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-6">
            <div>
              <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono">
                Inspect Image for Embedded Cryptographic Seal
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Upload any PNG image to extract LSB channels, authenticate ciphertext with AES-GCM, and verify the ECDSA signature against the case ledger.
              </p>
            </div>

            <input
              type="file"
              ref={extractFileInputRef}
              onChange={handleExtractFileSelect}
              accept="image/png"
              className="hidden"
            />

            {/* Upload Area */}
            {!extractImageSrc ? (
              <div
                onClick={() => extractFileInputRef.current?.click()}
                className="border-2 border-dashed border-slate-700 hover:border-cyan-500/60 rounded-xl p-8 text-center cursor-pointer transition-colors bg-slate-950/40 hover:bg-slate-900/50"
              >
                <div className="w-12 h-12 rounded-full bg-slate-800 flex items-center justify-center mx-auto mb-3 text-slate-300">
                  <Upload className="w-6 h-6 text-cyan-400" />
                </div>
                <p className="text-sm font-medium text-slate-200">
                  Click to select PNG image with embedded seal
                </p>
                <p className="text-xs text-slate-500 mt-1 font-mono">
                  Lossless PNG format required for bit-level extraction.
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-stretch">
                {/* Selected Image Preview */}
                <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 flex flex-col justify-between">
                  <div className="flex items-center justify-between mb-2 text-xs font-mono text-slate-400">
                    <span>Uploaded Target: {extractFileName}</span>
                    <button
                      onClick={() => extractFileInputRef.current?.click()}
                      className="text-cyan-400 hover:underline"
                    >
                      Change
                    </button>
                  </div>
                  <div className="flex-1 flex items-center justify-center max-h-56 overflow-hidden rounded bg-black/40">
                    <img
                      src={extractImageSrc}
                      alt="Extract Candidate"
                      className="max-h-52 w-auto object-contain rounded"
                    />
                  </div>
                </div>

                {/* Passphrase & Extraction Controls */}
                <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 flex flex-col justify-between space-y-4">
                  <div>
                    <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                      Decryption Passphrase *
                    </label>
                    <div className="relative">
                      <input
                        type={showExtractPassphrase ? 'text' : 'password'}
                        value={extractPassphrase}
                        onChange={(e) => setExtractPassphrase(e.target.value)}
                        placeholder="Enter the passphrase used during sealing"
                        className="w-full px-3 py-2 pr-10 text-sm bg-slate-900 border border-slate-700 rounded-md text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
                      />
                      <button
                        type="button"
                        onClick={() => setShowExtractPassphrase(!showExtractPassphrase)}
                        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 p-1"
                      >
                        {showExtractPassphrase ? (
                          <EyeOff className="w-4 h-4" />
                        ) : (
                          <Eye className="w-4 h-4" />
                        )}
                      </button>
                    </div>
                    <p className="text-[11px] text-slate-500 mt-1 font-mono">
                      PBKDF2 derives the AES-GCM key and verifies ciphertext integrity.
                    </p>
                  </div>

                  <button
                    onClick={handleExtractSeal}
                    disabled={isExtracting}
                    className="w-full py-2.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 rounded-md transition-colors flex items-center justify-center gap-2 shadow-sm shadow-cyan-950"
                  >
                    {isExtracting ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Reading LSB Channels & Decrypting...</span>
                      </>
                    ) : (
                      <>
                        <Key className="w-3.5 h-3.5" />
                        <span>Extract & Decrypt Hidden Seal</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Extraction & Verification Results */}
          {extractionResult && (
            <div className="space-y-4 animate-in fade-in duration-200">
              {/* Status State 1: SEAL VALID */}
              {extractionResult.status === 'VALID' && extractionResult.payload && (
                <div className="p-6 rounded-xl bg-emerald-950/40 border border-emerald-500/70 space-y-5 shadow-xl">
                  <div className="flex items-center justify-between pb-3 border-b border-emerald-800/60">
                    <div className="flex items-center gap-2.5 text-emerald-400">
                      <ShieldCheck className="w-6 h-6" />
                      <div>
                        <h3 className="text-sm font-bold font-mono uppercase tracking-wider">
                          Seal Valid: Cryptographic Custody Authenticated
                        </h3>
                        <p className="text-xs text-emerald-300/80">
                          Decryption succeeded. Digital signature verified and ledger head hash validated.
                        </p>
                      </div>
                    </div>
                    <span className="text-xs font-mono font-bold bg-emerald-900/80 border border-emerald-700 text-emerald-200 px-2.5 py-1 rounded">
                      ADMISSIBLE IN COURT
                    </span>
                  </div>

                  {/* Verification Badges */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                    <div className="p-3 rounded-lg bg-slate-950/80 border border-emerald-800/60 flex items-center gap-2 text-emerald-300">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                      <span>ECDSA P-256 Digital Signature: Authenticated</span>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-950/80 border border-emerald-800/60 flex items-center gap-2 text-emerald-300">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                      <span>Ledger Head Hash: {extractionResult.ledgerHeadMatchDetails}</span>
                    </div>
                  </div>

                  {/* Recovered Data Panel */}
                  <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs space-y-3">
                    <span className="text-[11px] font-mono uppercase text-slate-500 block">
                      Recovered Steganographic Payload Data:
                    </span>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-slate-300">
                      <div>
                        <span className="text-slate-500">Case ID:</span>{' '}
                        <span className="text-cyan-300 font-bold">{extractionResult.payload.caseId}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Evidence ID:</span>{' '}
                        <span className="text-cyan-300 font-bold">{extractionResult.payload.evidenceId}</span>
                      </div>
                      <div className="truncate">
                        <span className="text-slate-500">Original SHA-256:</span>{' '}
                        <span className="text-slate-200">{extractionResult.payload.originalImageHash}</span>
                      </div>
                      <div className="truncate">
                        <span className="text-slate-500">Ledger Head Hash:</span>{' '}
                        <span className="text-amber-300">{extractionResult.payload.ledgerHeadHash}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Sealed By:</span>{' '}
                        <span className="text-slate-200">
                          {extractionResult.payload.signerName} ({extractionResult.payload.signerRole})
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500">Timestamp:</span>{' '}
                        <span className="text-slate-400">{extractionResult.payload.timestamp}</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Status State 2: WRONG PASSPHRASE / CORRUPTED */}
              {extractionResult.status === 'WRONG_PASSPHRASE_OR_CORRUPT' && (
                <div className="p-6 rounded-xl bg-rose-950/40 border border-rose-600/80 space-y-3 shadow-xl">
                  <div className="flex items-center gap-2.5 text-rose-400">
                    <ShieldAlert className="w-6 h-6 shrink-0" />
                    <div>
                      <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-rose-200">
                        Wrong Passphrase / Corrupted
                      </h3>
                      <p className="text-xs text-rose-300">
                        {extractionResult.errorMessage ||
                          'AES-GCM decryption failed. The passphrase does not match or the LSB channel data was altered/corrupted.'}
                      </p>
                    </div>
                  </div>
                  <div className="text-[11px] font-mono text-slate-400 bg-slate-950/80 p-3 rounded border border-rose-900/60">
                    AES-GCM utilizes a 128-bit authentication tag. Any modification to a single bit or using an incorrect password causes immediate cryptographic rejection.
                  </div>
                </div>
              )}

              {/* Status State 3: NO HIDDEN SEAL FOUND */}
              {extractionResult.status === 'NO_SEAL_FOUND' && (
                <div className="p-6 rounded-xl bg-slate-900 border border-slate-700 space-y-3 shadow-xl">
                  <div className="flex items-center gap-2.5 text-slate-300">
                    <AlertTriangle className="w-6 h-6 text-amber-400 shrink-0" />
                    <div>
                      <h3 className="text-sm font-bold font-mono uppercase tracking-wider text-slate-200">
                        No Hidden Seal Found
                      </h3>
                      <p className="text-xs text-slate-400">
                        {extractionResult.errorMessage ||
                          'This image does not contain a SealChain LSB cryptographic marker or the length header is invalid.'}
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
