/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  GitCommit,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Lock,
  PlusCircle,
  RefreshCw,
  Copy,
  Check,
  AlertTriangle,
  FileText,
  Key,
  Layers,
  Sparkles,
  ArrowRight,
  HelpCircle,
  Eye,
  Sliders,
  CheckCircle2,
  XCircle,
  ChevronRight,
  Database,
  Search,
} from 'lucide-react';
import {
  ForensicCase,
  EvidenceItem,
  CustodyBlock,
  UserProfile,
  MerkleTreeData,
  MerkleProof,
} from '../types/forensics';
import { buildMerkleTree, generateMerkleProof, verifyMerkleProof } from '../crypto/merkleTree';
import { createSignedBlock, signDataWithKey } from '../crypto/webCrypto';
import { RbacPermissions } from '../services/rbacService';

interface MerkleCaseSealModuleProps {
  currentCase: ForensicCase;
  currentUser: UserProfile;
  onUpdateCase: (updatedCase: ForensicCase) => void;
  onAddCustodyBlock: (newBlock: CustodyBlock) => void;
  onNavigateToLedger: () => void;
  onNavigateToReports: () => void;
}

export const MerkleCaseSealModule: React.FC<MerkleCaseSealModuleProps> = ({
  currentCase,
  currentUser,
  onUpdateCase,
  onAddCustodyBlock,
  onNavigateToLedger,
  onNavigateToReports,
}) => {
  // Ensure we have a working list of evidence items (at least the primary evidence)
  const defaultEvidenceList = useMemo(() => {
    if (currentCase.evidenceList && currentCase.evidenceList.length > 0) {
      return currentCase.evidenceList;
    }
    return [
      currentCase.evidence,
      {
        id: 'ev-preset-02',
        caseId: currentCase.caseId,
        evidenceId: 'EVD-RAM-002',
        collectorName: currentCase.evidence.collectorName,
        collectorAgency: currentCase.evidence.collectorAgency,
        collectorBadge: currentCase.evidence.collectorBadge,
        description: 'Volatile RAM Bitstream Dump (LiME Memory Capture .raw)',
        timestamp: new Date(Date.now() - 3600000 * 2).toISOString(),
        imageFileName: 'suspect_host_memory_dump.raw',
        imageFileSize: 8589934592,
        imageMimeType: 'application/octet-stream',
        imageDataUrl: '',
        sha256Hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      },
      {
        id: 'ev-preset-03',
        caseId: currentCase.caseId,
        evidenceId: 'EVD-CCTV-003',
        collectorName: currentCase.evidence.collectorName,
        collectorAgency: currentCase.evidence.collectorAgency,
        collectorBadge: currentCase.evidence.collectorBadge,
        description: 'Facility Entrance CCTV Video Segment (Channel 04 H.264)',
        timestamp: new Date(Date.now() - 3600000 * 4).toISOString(),
        imageFileName: 'hallway_camera_1080p.mp4',
        imageFileSize: 412589000,
        imageMimeType: 'video/mp4',
        imageDataUrl: '',
        sha256Hash: 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e',
      },
      {
        id: 'ev-preset-04',
        caseId: currentCase.caseId,
        evidenceId: 'EVD-LOGS-004',
        collectorName: currentCase.evidence.collectorName,
        collectorAgency: currentCase.evidence.collectorAgency,
        collectorBadge: currentCase.evidence.collectorBadge,
        description: 'RADIUS Authentication Syslog & Network Firewall Capture',
        timestamp: new Date(Date.now() - 3600000 * 6).toISOString(),
        imageFileName: 'radius_auth_traffic.pcapng',
        imageFileSize: 98450120,
        imageMimeType: 'application/vnd.tcpdump.pcap',
        imageDataUrl: '',
        sha256Hash: '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
      },
    ];
  }, [currentCase]);

  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>(defaultEvidenceList);
  const [merkleTree, setMerkleTree] = useState<MerkleTreeData | null>(null);
  const [selectedLeafIndex, setSelectedLeafIndex] = useState<number | null>(0);
  const [activeProof, setActiveProof] = useState<MerkleProof | null>(null);
  const [isSealing, setIsSealing] = useState<boolean>(false);
  const [isVerifyingTree, setIsVerifyingTree] = useState<boolean>(false);
  const [treeVerificationResult, setTreeVerificationResult] = useState<{
    isValid: boolean;
    brokenLeafId?: string;
    details: string;
  } | null>(null);

  // Tamper demo state
  const [tamperedEvidenceId, setTamperedEvidenceId] = useState<string | null>(null);
  const [originalHashes, setOriginalHashes] = useState<Record<string, string>>({});
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Add evidence modal state
  const [isAddEvidenceModalOpen, setIsAddEvidenceModalOpen] = useState<boolean>(false);
  const [newEvidenceLabel, setNewEvidenceLabel] = useState<string>('');
  const [newEvidenceHash, setNewEvidenceHash] = useState<string>('');
  const [newEvidenceDesc, setNewEvidenceDesc] = useState<string>('');

  const canSeal = RbacPermissions.canSealCaseMerkle(currentUser.role);
  const canAddEv = RbacPermissions.canAddEvidence(currentUser.role);

  // Calculate Merkle tree whenever evidenceList changes
  useEffect(() => {
    let isMounted = true;
    const inputs = evidenceList.map((ev) => ({
      id: ev.id,
      label: `${ev.evidenceId}: ${ev.description.substring(0, 24)}...`,
      sha256Hash: ev.sha256Hash,
    }));

    buildMerkleTree(inputs).then((tree) => {
      if (isMounted) {
        setMerkleTree(tree);
      }
    });

    return () => {
      isMounted = false;
    };
  }, [evidenceList]);

  // Update active proof when selected leaf changes
  useEffect(() => {
    if (!merkleTree || selectedLeafIndex === null || selectedLeafIndex >= evidenceList.length) {
      setActiveProof(null);
      return;
    }

    const item = evidenceList[selectedLeafIndex];
    if (!item) return;

    generateMerkleProof(
      merkleTree,
      selectedLeafIndex,
      item.evidenceId,
      item.description
    ).then((proof) => {
      setActiveProof(proof);
    });
  }, [merkleTree, selectedLeafIndex, evidenceList]);

  // Seal Case action
  const handleSealCase = async () => {
    if (!merkleTree || !canSeal.allowed) return;

    setIsSealing(true);
    try {
      const rootHash = merkleTree.root;

      // Cryptographically sign the Merkle Root with the acting examiner's ECDSA P-256 private key
      const signatureHex = await signDataWithKey(rootHash, currentUser.privateKeyJwk);

      // Create new Merkle seal record
      const merkleSeal = {
        merkleRoot: rootHash,
        sealedAt: new Date().toISOString(),
        sealedBy: currentUser.name,
        sealedByRole: currentUser.title,
        signatureHex,
        evidenceCount: evidenceList.length,
        evidenceHashes: evidenceList.map((e) => ({
          evidenceId: e.evidenceId,
          sha256Hash: e.sha256Hash,
          label: e.description,
        })),
      };

      // Create Case Sealed Block on the custody ledger
      const headBlock = currentCase.blocks[currentCase.blocks.length - 1];
      const prevHash = headBlock ? headBlock.currentHash : '0000000000000000000000000000000000000000000000000000000000000000';
      const nextIndex = currentCase.blocks.length;

      const sealedBlock = await createSignedBlock({
        blockIndex: nextIndex,
        previousHash: prevHash,
        eventType: 'CASE_SEALED',
        actor: {
          id: currentUser.id,
          name: currentUser.name,
          role: currentUser.role,
          agency: currentUser.agency,
          badgeNumber: currentUser.badge,
          publicKeyJwk: currentUser.publicKeyJwk,
          privateKeyJwk: currentUser.privateKeyJwk,
        },
        details: {
          action: `Cryptographic Merkle Tree Case Seal: ${evidenceList.length} Specimens Sealed`,
          departmentOrAgency: currentUser.agency,
          facilityLocation: 'State Cyber Forensics Central Evidence Depository',
          toolOrMethodUsed: 'SealChain Merkle Tree Engine (RFC 6962 SHA-256 + ECDSA P-256 Root Seal)',
          notes: `Merkle Root: ${rootHash}. Bound specimens count: ${evidenceList.length}. Signature: ${signatureHex.substring(0, 24)}...`,
          authorizationReference: `Case Manifest Seal Certificate #${currentCase.caseId}-MKL-${Date.now().toString().slice(-6)}`,
        },
        evidenceId: currentCase.evidence.evidenceId,
        evidenceHash: rootHash,
      });

      // Update case
      const updatedCase: ForensicCase = {
        ...currentCase,
        evidenceList,
        merkleSeal,
        blocks: [...currentCase.blocks, sealedBlock],
      };

      onUpdateCase(updatedCase);
      onAddCustodyBlock(sealedBlock);

      setTreeVerificationResult({
        isValid: true,
        details: `Case sealed successfully. Root signed with ECDSA P-256 by ${currentUser.name} and appended as Ledger Block #${nextIndex}.`,
      });
    } catch (err) {
      console.error('Case sealing error:', err);
    } finally {
      setIsSealing(false);
    }
  };

  // Verify Case action
  const handleVerifyCase = async () => {
    if (!merkleTree) return;
    setIsVerifyingTree(true);

    try {
      // If the case was previously sealed, compare with recorded root
      if (currentCase.merkleSeal) {
        const expectedRoot = currentCase.merkleSeal.merkleRoot;
        const currentRoot = merkleTree.root;

        if (expectedRoot.toLowerCase() === currentRoot.toLowerCase()) {
          setTreeVerificationResult({
            isValid: true,
            details: `All ${evidenceList.length} specimens cryptographically verified! Merkle root matches sealed judicial manifest: ${currentRoot.substring(0, 16)}...`,
          });
        } else {
          // Find which specimen broke
          let brokenId: string | undefined;
          for (const ev of evidenceList) {
            const recorded = currentCase.merkleSeal.evidenceHashes.find((h) => h.evidenceId === ev.evidenceId);
            if (!recorded || recorded.sha256Hash.toLowerCase() !== ev.sha256Hash.toLowerCase()) {
              brokenId = ev.id;
              break;
            }
          }

          setTreeVerificationResult({
            isValid: false,
            brokenLeafId: brokenId,
            details: `INTEGRITY VIOLATION DETECTED! Computed Merkle root differs from signed seal. Evidence specimen [${brokenId || 'altered specimen'}] has been modified!`,
          });
        }
      } else {
        // Unsealed verification
        setTreeVerificationResult({
          isValid: true,
          details: `Merkle tree computed over ${evidenceList.length} evidence specimens. Root: ${merkleTree.root.substring(0, 20)}... (Case is currently unsealed; click "Seal Case" to bind into the custody ledger).`,
        });
      }
    } finally {
      setIsVerifyingTree(false);
    }
  };

  // Tamper with a specimen demo
  const handleTamperSpecimen = (evidenceId: string) => {
    const target = evidenceList.find((e) => e.id === evidenceId);
    if (!target) return;

    // Save original hash if not saved
    if (!originalHashes[evidenceId]) {
      setOriginalHashes((prev) => ({ ...prev, [evidenceId]: target.sha256Hash }));
    }

    // Flip bits in the hash
    const alteredHash = 'deadbeef' + target.sha256Hash.substring(8);
    setTamperedEvidenceId(evidenceId);

    setEvidenceList((prev) =>
      prev.map((e) => (e.id === evidenceId ? { ...e, sha256Hash: alteredHash } : e))
    );

    setTreeVerificationResult({
      isValid: false,
      brokenLeafId: evidenceId,
      details: `DEMO TAMPERING APPLIED to specimen "${target.evidenceId}". The leaf hash changed, invalidating the parent branches up to the root!`,
    });
  };

  // Restore tampered specimen
  const handleRestoreSpecimen = (evidenceId: string) => {
    const originalHash = originalHashes[evidenceId];
    if (!originalHash) return;

    setEvidenceList((prev) =>
      prev.map((e) => (e.id === evidenceId ? { ...e, sha256Hash: originalHash } : e))
    );
    setTamperedEvidenceId(null);
    setTreeVerificationResult(null);
  };

  // Add new evidence item
  const handleAddNewEvidence = () => {
    if (!newEvidenceLabel || !newEvidenceHash) return;

    const newEv: EvidenceItem = {
      id: `ev-custom-${Date.now()}`,
      caseId: currentCase.caseId,
      evidenceId: `EVD-EXT-${Date.now().toString().slice(-4)}`,
      collectorName: currentUser.name,
      collectorAgency: currentUser.agency,
      collectorBadge: currentUser.badge,
      description: newEvidenceDesc || newEvidenceLabel,
      timestamp: new Date().toISOString(),
      imageFileName: newEvidenceLabel,
      imageFileSize: 1048576,
      imageMimeType: 'application/octet-stream',
      imageDataUrl: '',
      sha256Hash: newEvidenceHash.toLowerCase().trim(),
    };

    setEvidenceList((prev) => [...prev, newEv]);
    setNewEvidenceLabel('');
    setNewEvidenceHash('');
    setNewEvidenceDesc('');
    setIsAddEvidenceModalOpen(false);
  };

  const copyToClipboard = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const isCaseSealed = !!currentCase.merkleSeal;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-cyan-950/70 border border-cyan-500/40 text-cyan-400">
              <GitCommit className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-slate-100">
                  Merkle Tree Case Seal & Selective Proofs
                </h1>
                {isCaseSealed ? (
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-950 border border-emerald-700 text-emerald-300 flex items-center gap-1 font-semibold">
                    <CheckCircle2 className="w-3 h-3" />
                    <span>Case Sealed (ECDSA)</span>
                  </span>
                ) : (
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-amber-950 border border-amber-700 text-amber-300 flex items-center gap-1 font-semibold">
                    <AlertTriangle className="w-3 h-3" />
                    <span>Unsealed Manifest</span>
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400">
                Cryptographically binds multiple digital evidence specimens into a single immutable SHA-256 Merkle root with selective inclusion proofs.
              </p>
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-3">
          {canAddEv.allowed && (
            <button
              onClick={() => setIsAddEvidenceModalOpen(true)}
              className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <PlusCircle className="w-4 h-4 text-cyan-400" />
              <span>Add Specimen Hash</span>
            </button>
          )}

          <button
            onClick={handleVerifyCase}
            disabled={isVerifyingTree}
            className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-4 h-4 text-cyan-400 ${isVerifyingTree ? 'animate-spin' : ''}`} />
            <span>Verify Case Tree</span>
          </button>

          <button
            onClick={handleSealCase}
            disabled={isSealing || !canSeal.allowed}
            className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-semibold text-xs font-mono flex items-center gap-2 shadow-lg shadow-cyan-950/50 transition-all cursor-pointer"
            title={canSeal.allowed ? 'Seal this case manifest' : canSeal.reason}
          >
            {isSealing ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Signing Merkle Root...</span>
              </>
            ) : (
              <>
                <Lock className="w-4 h-4" />
                <span>Seal Case Manifest (ECDSA)</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Verification Result Banner */}
      {treeVerificationResult && (
        <div
          className={`p-4 rounded-xl border flex items-start gap-3 shadow-lg ${
            treeVerificationResult.isValid
              ? 'bg-emerald-950/60 border-emerald-600/70 text-emerald-200'
              : 'bg-rose-950/70 border-rose-600 text-rose-200 animate-pulse'
          }`}
        >
          {treeVerificationResult.isValid ? (
            <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
          ) : (
            <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          )}
          <div className="space-y-1">
            <div className="text-xs font-bold font-mono uppercase tracking-wider">
              {treeVerificationResult.isValid ? 'Cryptographic Tree Integrity Confirmed' : 'Integrity Compromise Detected'}
            </div>
            <p className="text-xs font-mono leading-relaxed">{treeVerificationResult.details}</p>
          </div>
        </div>
      )}

      {/* Main Grid: Tree Visualization + Evidence List + Merkle Proof */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Interactive Merkle Tree Visualization (2 cols) */}
        <div className="lg:col-span-2 space-y-6">
          {/* Tree Diagram Card */}
          <div className="p-6 rounded-xl bg-slate-950 border border-slate-800 shadow-xl space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
              <div>
                <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
                  <Layers className="w-4 h-4 text-cyan-400" />
                  <span>Binary Merkle Tree Architecture</span>
                </h2>
                <p className="text-xs text-slate-400">
                  Click on any evidence leaf to trace its cryptographic sibling proof path to the root.
                </p>
              </div>

              {merkleTree && (
                <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg text-xs font-mono">
                  <span className="text-slate-400">Root:</span>
                  <span className="text-cyan-300 font-bold">{merkleTree.root.substring(0, 16)}...</span>
                  <button
                    onClick={() => copyToClipboard('root-hash', merkleTree.root)}
                    className="text-slate-400 hover:text-slate-200 ml-1"
                    title="Copy full 64-char root hash"
                  >
                    {copiedKey === 'root-hash' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              )}
            </div>

            {/* Tree Diagram Nodes */}
            {merkleTree ? (
              <div className="space-y-6 py-2">
                {/* Levels rendering (from Root down to Leaves) */}
                {merkleTree.levels
                  .slice()
                  .reverse()
                  .map((levelHashes, reversedLvlIdx) => {
                    const actualLevel = merkleTree.levels.length - 1 - reversedLvlIdx;
                    const isRootLevel = actualLevel === merkleTree.levels.length - 1;
                    const isLeafLevel = actualLevel === 0;

                    return (
                      <div key={actualLevel} className="space-y-2">
                        <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 uppercase tracking-wider">
                          <span>
                            {isRootLevel
                              ? 'Level (Root)'
                              : isLeafLevel
                              ? 'Level 0 (Evidence Leaves)'
                              : `Intermediate Level ${actualLevel}`}
                          </span>
                          <span>{levelHashes.length} Node(s)</span>
                        </div>

                        <div className="flex flex-wrap items-center justify-center gap-3">
                          {levelHashes.map((hash, nodeIdx) => {
                            const isLeaf = isLeafLevel;
                            const isSelectedLeaf = isLeaf && selectedLeafIndex === nodeIdx;
                            const isBrokenNode =
                              treeVerificationResult?.brokenLeafId &&
                              isLeaf &&
                              evidenceList[nodeIdx]?.id === treeVerificationResult.brokenLeafId;

                            return (
                              <button
                                key={`${actualLevel}-${nodeIdx}`}
                                onClick={() => {
                                  if (isLeaf) setSelectedLeafIndex(nodeIdx);
                                }}
                                className={`p-3 rounded-lg border text-left font-mono transition-all text-xs max-w-xs flex-1 min-w-[210px] ${
                                  isBrokenNode
                                    ? 'bg-rose-950/80 border-rose-500 text-rose-200 shadow-lg shadow-rose-950/50'
                                    : isSelectedLeaf
                                    ? 'bg-cyan-950/80 border-cyan-400 text-cyan-200 shadow-lg shadow-cyan-950/50 ring-2 ring-cyan-500/40'
                                    : isRootLevel
                                    ? 'bg-purple-950/50 border-purple-700/80 text-purple-200'
                                    : 'bg-slate-900 border-slate-800 hover:border-slate-700 text-slate-300'
                                }`}
                              >
                                <div className="flex items-center justify-between text-[10px] pb-1 border-b border-white/5 mb-1.5 opacity-75">
                                  <span>
                                    {isRootLevel
                                      ? '👑 CASE MERKLE ROOT'
                                      : isLeaf
                                      ? `SPECIMEN #${nodeIdx + 1}`
                                      : `PARENT NODE [${nodeIdx}]`}
                                  </span>
                                  {isLeaf && <span>Click to Trace</span>}
                                </div>
                                <div className="text-[11px] font-bold truncate">
                                  {isLeaf ? evidenceList[nodeIdx]?.description || `Evidence ${nodeIdx + 1}` : `SHA-256 Hash`}
                                </div>
                                <div className="text-[10px] text-slate-400 font-mono mt-1 flex items-center justify-between">
                                  <span>{hash.substring(0, 14)}...{hash.substring(hash.length - 6)}</span>
                                  <span className="text-[9px] uppercase px-1 py-0.5 rounded bg-black/40">
                                    {isLeaf ? 'Leaf' : 'Node'}
                                  </span>
                                </div>
                              </button>
                            );
                          })}
                        </div>

                        {/* Connector line down to next level */}
                        {!isLeafLevel && (
                          <div className="flex justify-center py-1">
                            <div className="w-0.5 h-4 bg-slate-800" />
                          </div>
                        )}
                      </div>
                    );
                  })}
              </div>
            ) : (
              <div className="p-8 text-center text-xs font-mono text-slate-400">
                Constructing Merkle Tree...
              </div>
            )}
          </div>

          {/* Evidence List & Tampering Lab */}
          <div className="p-6 rounded-xl bg-slate-950 border border-slate-800 shadow-xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div>
                <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono">
                  Specimens Included in this Case ({evidenceList.length})
                </h3>
                <p className="text-xs text-slate-400">
                  Every specimen has an immutable FIPS 180-4 SHA-256 digest linked to the case root.
                </p>
              </div>

              {tamperedEvidenceId && (
                <button
                  onClick={() => handleRestoreSpecimen(tamperedEvidenceId)}
                  className="px-3 py-1 text-xs font-mono text-emerald-300 bg-emerald-950 border border-emerald-700 rounded-md hover:bg-emerald-900 transition-colors flex items-center gap-1"
                >
                  <RefreshCw className="w-3 h-3" />
                  <span>Restore Original Specimen</span>
                </button>
              )}
            </div>

            <div className="space-y-3">
              {evidenceList.map((ev, idx) => {
                const isSelected = selectedLeafIndex === idx;
                const isTampered = tamperedEvidenceId === ev.id;

                return (
                  <div
                    key={ev.id}
                    className={`p-3.5 rounded-lg border transition-all text-xs font-mono flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                      isTampered
                        ? 'bg-rose-950/40 border-rose-600/80'
                        : isSelected
                        ? 'bg-slate-900 border-cyan-500/70'
                        : 'bg-slate-900/60 border-slate-800'
                    }`}
                  >
                    <div className="space-y-1 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-200">{ev.evidenceId}</span>
                        <span className="text-[10px] text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">
                          Leaf #{idx}
                        </span>
                        {isTampered && (
                          <span className="text-[10px] text-rose-300 bg-rose-950 border border-rose-800 px-1.5 py-0.5 rounded font-bold">
                            TAMPERED HASH
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-slate-300">{ev.description}</p>
                      <div className="text-[11px] text-cyan-300/80 truncate">
                        SHA-256: {ev.sha256Hash}
                      </div>
                    </div>

                    <div className="flex items-center gap-2 self-start sm:self-auto shrink-0">
                      <button
                        onClick={() => setSelectedLeafIndex(idx)}
                        className={`px-2.5 py-1.5 rounded border text-[11px] transition-colors ${
                          isSelected
                            ? 'bg-cyan-950 text-cyan-300 border-cyan-700'
                            : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
                        }`}
                      >
                        Inspect Proof
                      </button>

                      {RbacPermissions.canTamperDemo(currentUser.role).allowed && (
                        <>
                          {isTampered ? (
                            <button
                              onClick={() => handleRestoreSpecimen(ev.id)}
                              className="px-2.5 py-1.5 rounded bg-emerald-950 hover:bg-emerald-900 border border-emerald-700 text-emerald-200 text-[11px] transition-colors"
                            >
                              Restore
                            </button>
                          ) : (
                            <button
                              onClick={() => handleTamperSpecimen(ev.id)}
                              className="px-2.5 py-1.5 rounded bg-rose-950 hover:bg-rose-900 border border-rose-700 text-rose-200 text-[11px] transition-colors"
                              title="Demonstrate how altering a single specimen invalidates its branch"
                            >
                              Tamper Demo
                            </button>
                          )}
                        </>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right Column: Single Evidence Merkle Proof & Selective Disclosure (1 col) */}
        <div className="space-y-6">
          {/* Merkle Proof Card */}
          <div className="p-6 rounded-xl bg-slate-950 border border-slate-800 shadow-xl space-y-4">
            <div className="pb-3 border-b border-slate-800">
              <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>Single Evidence Inclusion Proof</span>
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Cryptographically proves this item belongs to the case without exposing sibling evidence items.
              </p>
            </div>

            {activeProof ? (
              <div className="space-y-4 text-xs font-mono">
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1.5">
                  <div className="text-[10px] text-slate-400 uppercase">Selected Specimen:</div>
                  <div className="text-slate-100 font-bold">{activeProof.label}</div>
                  <div className="text-[10px] text-cyan-300 truncate">
                    Leaf Hash: {activeProof.leafHash}
                  </div>
                </div>

                {/* Sibling Path Table */}
                <div className="space-y-2">
                  <div className="text-[11px] font-bold text-slate-300 uppercase tracking-wider">
                    Log₂(N) Sibling Proof Path ({activeProof.proof.length} Steps):
                  </div>

                  {activeProof.proof.map((step, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 space-y-1"
                    >
                      <div className="flex items-center justify-between text-[10px] text-slate-400">
                        <span>Step {idx + 1}: Concatenate {step.position.toUpperCase()}</span>
                        <span className="px-1.5 py-0.5 rounded bg-black/40 font-bold">
                          {step.position === 'left' ? 'Sibling + Current' : 'Current + Sibling'}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-300 truncate">
                        Sibling: {step.siblingHash.substring(0, 20)}...{step.siblingHash.slice(-8)}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Self Verification Result */}
                <div
                  className={`p-3 rounded-lg border flex items-center gap-2.5 ${
                    activeProof.isVerified
                      ? 'bg-emerald-950/60 border-emerald-700 text-emerald-200'
                      : 'bg-rose-950/60 border-rose-700 text-rose-200'
                  }`}
                >
                  {activeProof.isVerified ? (
                    <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
                  ) : (
                    <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0" />
                  )}
                  <div>
                    <div className="font-bold text-[11px]">
                      {activeProof.isVerified
                        ? 'PROOF VERIFIED: INCLUSION CONFIRMED'
                        : 'PROOF REJECTED: PATH INVALID'}
                    </div>
                    <div className="text-[10px] opacity-80">
                      {activeProof.isVerified
                        ? 'Reconstructed root equals signed case Merkle root.'
                        : 'Reconstructed root does not match signed case Merkle root.'}
                    </div>
                  </div>
                </div>

                {/* Plain-English Legal Rationale */}
                <div className="p-3.5 rounded-lg bg-cyan-950/30 border border-cyan-800/40 text-cyan-200/90 text-xs leading-relaxed space-y-1.5">
                  <div className="font-bold text-[11px] flex items-center gap-1.5 text-cyan-300">
                    <HelpCircle className="w-3.5 h-3.5" />
                    <span>Why Merkle Proofs Are Crucial in Court:</span>
                  </div>
                  <p>
                    Under Federal Rule of Evidence 901, an investigator can present this specific item in trial with absolute mathematical proof that it was part of the sealed case at seizure time—without disclosing confidential or privileged sibling files.
                  </p>
                </div>
              </div>
            ) : (
              <div className="p-6 text-center text-xs font-mono text-slate-400">
                Select an evidence item from the list to view its Merkle proof.
              </div>
            )}
          </div>

          {/* Sealed Case Audit Summary Card */}
          {currentCase.merkleSeal && (
            <div className="p-6 rounded-xl bg-slate-950 border border-emerald-900/60 shadow-xl space-y-3">
              <div className="flex items-center gap-2 text-emerald-400 font-mono font-bold text-xs uppercase">
                <ShieldCheck className="w-4 h-4" />
                <span>Sealed Case Manifest Details</span>
              </div>

              <div className="space-y-1.5 text-xs font-mono text-slate-300">
                <div>
                  <span className="text-slate-400">Sealed By:</span> {currentCase.merkleSeal.sealedBy}
                </div>
                <div>
                  <span className="text-slate-400">Role:</span> {currentCase.merkleSeal.sealedByRole}
                </div>
                <div>
                  <span className="text-slate-400">Timestamp:</span>{' '}
                  {currentCase.merkleSeal.sealedAt.replace('T', ' ').substring(0, 19)}
                </div>
                <div>
                  <span className="text-slate-400">Total Bound Items:</span>{' '}
                  {currentCase.merkleSeal.evidenceCount} Specimens
                </div>
                <div className="pt-2 border-t border-slate-800">
                  <div className="text-[10px] text-slate-400">ECDSA P-256 Signature:</div>
                  <div className="text-[10px] text-emerald-300 truncate">
                    {currentCase.merkleSeal.signatureHex}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Modal: Add Evidence Item */}
      {isAddEvidenceModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-slate-100 font-mono flex items-center gap-2">
              <PlusCircle className="w-5 h-5 text-cyan-400" />
              <span>Add Evidence Specimen Hash</span>
            </h3>

            <div className="space-y-3 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Specimen Filename / Label:</label>
                <input
                  type="text"
                  value={newEvidenceLabel}
                  onChange={(e) => setNewEvidenceLabel(e.target.value)}
                  placeholder="e.g. disk_image_sector0.bin"
                  className="w-full bg-slate-950 border border-slate-700 rounded p-2 text-slate-100"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">SHA-256 Digest (64 hex):</label>
                <input
                  type="text"
                  value={newEvidenceHash}
                  onChange={(e) => setNewEvidenceHash(e.target.value)}
                  placeholder="e.g. e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                  className="w-full bg-slate-950 border border-slate-700 rounded p-2 text-slate-100"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Description / Custody Note:</label>
                <input
                  type="text"
                  value={newEvidenceDesc}
                  onChange={(e) => setNewEvidenceDesc(e.target.value)}
                  placeholder="e.g. Encrypted SSD clone captured under Warrant #442"
                  className="w-full bg-slate-950 border border-slate-700 rounded p-2 text-slate-100"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                onClick={() => setIsAddEvidenceModalOpen(false)}
                className="px-3 py-1.5 rounded bg-slate-800 text-slate-300 text-xs font-mono hover:bg-slate-700"
              >
                Cancel
              </button>
              <button
                onClick={handleAddNewEvidence}
                disabled={!newEvidenceLabel || !newEvidenceHash}
                className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-slate-950 font-bold text-xs font-mono"
              >
                Add Specimen to Case
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
