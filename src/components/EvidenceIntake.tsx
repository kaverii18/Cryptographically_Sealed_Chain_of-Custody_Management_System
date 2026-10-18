/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef, useEffect } from 'react';
import {
  Upload,
  Copy,
  Check,
  ShieldCheck,
  Cpu,
  FileImage,
  RefreshCw,
  Sparkles,
  Info,
} from 'lucide-react';
import { ActorIdentity, EvidenceItem, ForensicCase } from '../types/forensics';
import { computeFileSHA256, createSignedBlock, GENESIS_PREVIOUS_HASH } from '../crypto/webCrypto';
import { generateSampleForensicImage } from '../utils/sampleEvidence';
import { saveActiveCase, setAsBackupCase } from '../services/storageService';

interface EvidenceIntakeProps {
  actors: ActorIdentity[];
  onCaseCreated: (newCase: ForensicCase) => void;
  onCancel?: () => void;
}

export const EvidenceIntake: React.FC<EvidenceIntakeProps> = ({
  actors,
  onCaseCreated,
  onCancel,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Form states
  const [caseId, setCaseId] = useState('CAS-2026-9812');
  const [caseTitle, setCaseTitle] = useState('Operation DeepVault - Seized Storage Media');
  const [evidenceId, setEvidenceId] = useState('EVD-001-A');
  const [selectedActorId, setSelectedActorId] = useState(actors[0]?.id || '');
  const [customCollectorName, setCustomCollectorName] = useState(actors[0]?.name || 'Det. Elena Rostova');
  const [collectorAgency, setCollectorAgency] = useState(actors[0]?.agency || 'State Digital Crimes Division');
  const [collectorBadge, setCollectorBadge] = useState(actors[0]?.badgeNumber || 'CF-409');
  const [description, setDescription] = useState(
    'Seized Samsung 990 Pro 2TB M.2 NVMe SSD drive recovered from laboratory workstation B-4 during court-authorized search.'
  );

  // Image & Web Crypto states
  const [imageFile, setImageFile] = useState<File | Blob | null>(null);
  const [imagePreviewUrl, setImagePreviewUrl] = useState<string | null>(null);
  const [imageFileName, setImageFileName] = useState('');
  const [imageFileSize, setImageFileSize] = useState<number>(0);
  const [imageMimeType, setImageMimeType] = useState('image/png');
  const [sha256Hash, setSha256Hash] = useState<string>('');
  const [isHashing, setIsHashing] = useState<boolean>(false);
  const [hashDurationMs, setHashDurationMs] = useState<number | null>(null);
  const [isCopied, setIsCopied] = useState<boolean>(false);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Auto-timestamp (formatted)
  const [currentTimestamp, setCurrentTimestamp] = useState<string>(new Date().toISOString());

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTimestamp(new Date().toISOString());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Update selected actor info when dropdown changes
  const handleActorSelect = (actorId: string) => {
    setSelectedActorId(actorId);
    const actor = actors.find((a) => a.id === actorId);
    if (actor) {
      setCustomCollectorName(actor.name);
      setCollectorAgency(actor.agency);
      setCollectorBadge(actor.badgeNumber);
    }
  };

  // Helper to hash an uploaded file or blob
  const processImage = async (file: File | Blob, name: string) => {
    setErrorMessage(null);
    setIsHashing(true);
    setSha256Hash('');

    try {
      const startTime = performance.now();

      // Read as Data URL for preview
      const reader = new FileReader();
      const readPromise = new Promise<string>((resolve, reject) => {
        reader.onload = () => resolve(reader.result as string);
        reader.onerror = reject;
      });
      reader.readAsDataURL(file);
      const dataUrl = await readPromise;

      // Compute genuine SHA-256 via Web Crypto API
      const computedHash = await computeFileSHA256(file);
      const endTime = performance.now();

      setImageFile(file);
      setImagePreviewUrl(dataUrl);
      setImageFileName(name);
      setImageFileSize(file.size);
      setImageMimeType(file.type || 'image/png');
      setSha256Hash(computedHash);
      setHashDurationMs(Math.round(endTime - startTime));
    } catch (err: unknown) {
      console.error('Hashing error:', err);
      const msg = err instanceof Error ? err.message : 'Unknown hashing error';
      setErrorMessage(`Failed to calculate SHA-256 hash using Web Crypto: ${msg}`);
    } finally {
      setIsHashing(false);
    }
  };

  // Handle user file upload via file dialog
  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      if (!file.type.startsWith('image/')) {
        setErrorMessage('Only image files (PNG, JPG, WEBP, etc.) are supported for digital evidence intake.');
        return;
      }
      processImage(file, file.name);
    }
  };

  // Drag and drop handlers
  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    const file = e.dataTransfer.files?.[0];
    if (file) {
      if (!file.type.startsWith('image/')) {
        setErrorMessage('Only image files are supported for evidence intake.');
        return;
      }
      processImage(file, file.name);
    }
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
  };

  // Load sample forensic image
  const handleLoadSample = () => {
    const sample = generateSampleForensicImage();
    processImage(sample.blob, sample.fileName);
  };

  // Copy hash to clipboard
  const handleCopyHash = () => {
    if (!sha256Hash) return;
    navigator.clipboard.writeText(sha256Hash);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  // Seal & register Genesis Block
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!imagePreviewUrl || !sha256Hash) {
      setErrorMessage('Please upload an evidence image or generate a sample image first.');
      return;
    }
    if (!caseId.trim() || !evidenceId.trim() || !customCollectorName.trim()) {
      setErrorMessage('Please fill in all mandatory fields (Case ID, Evidence ID, Collector Name).');
      return;
    }

    setIsSubmitting(true);
    setErrorMessage(null);

    try {
      const activeActor = actors.find((a) => a.id === selectedActorId) || actors[0];

      const evidence: EvidenceItem = {
        id: `evd-${Date.now()}`,
        caseId: caseId.trim(),
        evidenceId: evidenceId.trim(),
        collectorName: customCollectorName.trim(),
        collectorAgency: collectorAgency.trim(),
        collectorBadge: collectorBadge.trim(),
        description: description.trim(),
        timestamp: currentTimestamp,
        imageFileName: imageFileName || 'seized_evidence_specimen.png',
        imageFileSize,
        imageMimeType,
        imageDataUrl: imagePreviewUrl,
        sha256Hash,
      };

      // Create Genesis Block (#0 COLLECTED) signed with ECDSA P-256
      const genesisBlock = await createSignedBlock({
        blockIndex: 0,
        previousHash: GENESIS_PREVIOUS_HASH,
        eventType: 'COLLECTED',
        actor: activeActor,
        details: {
          action: 'Initial physical evidence intake and forensic registration',
          departmentOrAgency: collectorAgency.trim(),
          facilityLocation: 'Initial Evidence Collection Site / Forensic Intake Desk',
          toolOrMethodUsed: 'Web Crypto API NIST FIPS 180-4 SHA-256 & ECDSA P-256 Seal',
          notes: description.trim(),
          authorizationReference: `Intake Log #${evidenceId.trim()}`,
        },
        evidenceId: evidence.evidenceId,
        evidenceHash: evidence.sha256Hash,
        timestamp: currentTimestamp,
      });

      const newCase: ForensicCase = {
        caseId: evidence.caseId,
        caseTitle: caseTitle.trim() || `Forensic Case ${evidence.caseId}`,
        createdAt: currentTimestamp,
        evidence,
        blocks: [genesisBlock],
      };

      // Save to localStorage
      saveActiveCase(newCase);
      setAsBackupCase(newCase);

      // Trigger callback
      onCaseCreated(newCase);
    } catch (err: unknown) {
      console.error('Genesis block creation error:', err);
      const msg = err instanceof Error ? err.message : 'Unknown error during seal creation';
      setErrorMessage(`Failed to seal genesis block: ${msg}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-8 px-4 sm:px-6">
      <div className="mb-8">
        <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-2">
          <span>MODULE 01</span>
          <span aria-hidden="true">·</span>
          <span>EVIDENCE INTAKE & HASH COMPUTATION</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-100">
          Sealed Evidence Intake
        </h1>
        <p className="mt-1 text-sm text-slate-400">
          Upload forensic digital media. The SHA-256 hash is computed in-browser using the native Web Crypto API and sealed into an ECDSA-signed genesis block.
        </p>
      </div>

      {errorMessage && (
        <div className="mb-6 p-4 rounded-lg bg-rose-950/40 border border-rose-600/60 text-rose-300 text-sm flex items-start gap-3">
          <Info className="w-5 h-5 shrink-0 text-rose-400 mt-0.5" />
          <div className="flex-1">
            <span className="font-semibold block">Intake Notice</span>
            <span>{errorMessage}</span>
          </div>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-8">
        {/* Step 1: Upload & Image Analysis */}
        <div className="p-6 rounded-xl bg-slate-900/70 border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <FileImage className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono">
                1. Digital Media Specimen (Image)
              </h2>
            </div>
            <button
              type="button"
              onClick={handleLoadSample}
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 px-2.5 py-1 rounded bg-cyan-950/60 border border-cyan-800/60 hover:bg-cyan-900/60 transition-colors"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Load Sample Forensic Drive Photo</span>
            </button>
          </div>

          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileInput}
            accept="image/*"
            className="hidden"
          />

          {!imagePreviewUrl ? (
            <div
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onClick={() => fileInputRef.current?.click()}
              className="border-2 border-dashed border-slate-700 hover:border-cyan-500/60 rounded-xl p-8 text-center cursor-pointer transition-colors bg-slate-950/40 hover:bg-slate-900/50"
            >
              <div className="w-12 h-12 rounded-full bg-slate-800 flex items-center justify-center mx-auto mb-3 text-slate-300">
                <Upload className="w-6 h-6 text-cyan-400" />
              </div>
              <p className="text-sm font-medium text-slate-200">
                Click to upload or drag & drop evidence image
              </p>
              <p className="text-xs text-slate-500 mt-1">
                Supports PNG, JPEG, WEBP, or TIFF. In-browser SHA-256 calculation.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-stretch">
                {/* Image Preview */}
                <div className="relative rounded-lg overflow-hidden bg-slate-950 border border-slate-800 flex items-center justify-center min-h-[220px]">
                  <img
                    src={imagePreviewUrl}
                    alt="Seized Evidence Preview"
                    className="max-h-64 w-auto object-contain"
                  />
                  <div className="absolute top-2 right-2 bg-slate-950/80 backdrop-blur-sm px-2 py-1 rounded text-[11px] font-mono text-slate-300 border border-slate-700">
                    {imageFileName} ({(imageFileSize / 1024).toFixed(1)} KB)
                  </div>
                </div>

                {/* Crypto Digest Inspection */}
                <div className="flex flex-col justify-between p-4 rounded-lg bg-slate-950 border border-slate-800">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-mono text-slate-400 uppercase">
                        Web Crypto SHA-256 Digest
                      </span>
                      {hashDurationMs !== null && (
                        <span className="text-[11px] font-mono text-cyan-400">
                          Computed in {hashDurationMs} ms
                        </span>
                      )}
                    </div>

                    {isHashing ? (
                      <div className="flex items-center gap-2 py-4 text-cyan-400 font-mono text-xs">
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>Streaming bytes to crypto.subtle.digest...</span>
                      </div>
                    ) : (
                      <div className="space-y-3">
                        <div className="p-2.5 rounded bg-slate-900 border border-slate-800 font-mono text-xs text-cyan-300 break-all select-all leading-relaxed">
                          {sha256Hash}
                        </div>

                        <div className="flex items-center justify-between">
                          <button
                            type="button"
                            onClick={handleCopyHash}
                            className="px-2.5 py-1 text-xs font-mono text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 flex items-center gap-1.5 transition-colors"
                          >
                            {isCopied ? (
                              <>
                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                                <span className="text-emerald-400">Copied to Clipboard</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3.5 h-3.5" />
                                <span>Copy SHA-256</span>
                              </>
                            )}
                          </button>

                          <div className="flex items-center gap-1 text-[11px] font-mono text-emerald-400">
                            <ShieldCheck className="w-3.5 h-3.5" />
                            <span>Bit-Exact Signature Base</span>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="pt-4 mt-4 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400 font-mono">
                    <span>Algorithm: NIST SHA-256</span>
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      className="text-cyan-400 hover:text-cyan-300 underline underline-offset-2"
                    >
                      Replace Specimen
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Step 2: Forensic Metadata */}
        <div className="p-6 rounded-xl bg-slate-900/70 border border-slate-800 space-y-6">
          <div className="flex items-center gap-2 mb-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono">
              2. Forensic Case & Custodian Parameters
            </h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                Case Identifier *
              </label>
              <input
                type="text"
                value={caseId}
                onChange={(e) => setCaseId(e.target.value)}
                required
                className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
                placeholder="e.g. CAS-2026-9812"
              />
            </div>

            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                Evidence Tag / ID *
              </label>
              <input
                type="text"
                value={evidenceId}
                onChange={(e) => setEvidenceId(e.target.value)}
                required
                className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
                placeholder="e.g. EVD-001-A"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
              Case Operation Title
            </label>
            <input
              type="text"
              value={caseTitle}
              onChange={(e) => setCaseTitle(e.target.value)}
              className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-cyan-500"
              placeholder="e.g. Operation DeepVault"
            />
          </div>

          {/* Collector Identification */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                Primary Collector / Actor *
              </label>
              <select
                value={selectedActorId}
                onChange={(e) => handleActorSelect(e.target.value)}
                className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-cyan-500"
              >
                {actors.map((actor) => (
                  <option key={actor.id} value={actor.id}>
                    {actor.name} ({actor.role})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                Department / Agency
              </label>
              <input
                type="text"
                value={collectorAgency}
                onChange={(e) => setCollectorAgency(e.target.value)}
                className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                Badge / Credential ID
              </label>
              <input
                type="text"
                value={collectorBadge}
                onChange={(e) => setCollectorBadge(e.target.value)}
                className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {/* Description */}
          <div>
            <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
              Evidence Physical Description & Seizure Context *
            </label>
            <textarea
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              required
              className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-cyan-500 resize-none"
              placeholder="Detail hardware make, model, serial, physical condition, recovery location, and packaging method."
            />
          </div>

          {/* Timestamp Indicator */}
          <div className="p-3 rounded bg-slate-950/80 border border-slate-800/80 flex items-center justify-between text-xs text-slate-400 font-mono">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              <span>Intake Timestamp (Auto):</span>
            </span>
            <span className="text-slate-200">{currentTimestamp}</span>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center justify-end gap-3 pt-2">
          {onCancel && (
            <button
              type="button"
              onClick={onCancel}
              className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-md transition-colors"
            >
              Cancel
            </button>
          )}

          <button
            type="submit"
            disabled={!sha256Hash || isSubmitting || isHashing}
            className="px-6 py-2.5 text-sm font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 disabled:cursor-not-allowed rounded-md transition-colors flex items-center gap-2 shadow-lg shadow-cyan-950/50"
          >
            {isSubmitting ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Signing Genesis Block (ECDSA P-256)...</span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-4 h-4" />
                <span>Seal & Register Genesis Block</span>
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};
