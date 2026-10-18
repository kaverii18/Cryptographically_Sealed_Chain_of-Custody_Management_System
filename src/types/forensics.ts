/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export type CustodyEventType =
  | 'COLLECTED'
  | 'TRANSFERRED'
  | 'ANALYZED'
  | 'STORED'
  | 'RELEASED'
  | 'SEALED'
  | 'WATERMARKED'
  | 'VERIFIED'
  | 'CASE_SEALED'
  | 'REPORT_GENERATED'
  | 'USER_LOGIN'
  | 'USER_LOGOUT'
  | 'ACCESS_DENIED';

export interface EventDetails {
  action: string;
  departmentOrAgency?: string;
  facilityLocation?: string;
  toolOrMethodUsed?: string; // e.g. FTK Imager, Autopsy, Faraday Bag, Evidence Locker B-12
  notes: string;
  recipientName?: string;
  recipientRole?: string;
  authorizationReference?: string; // e.g. Search Warrant #2026-44B, Court Order
}

export interface CustodyBlock {
  blockIndex: number;
  previousHash: string; // 64 hex characters or 64 zeroes for genesis
  timestamp: string; // ISO-8601
  eventType: CustodyEventType;
  actorName: string;
  actorRole: string;
  actorAgency: string;
  actorPublicKeyJwk: JsonWebKey;
  actorPublicKeyFingerprint: string; // First 16 hex chars of SHA-256 of public key
  details: EventDetails;
  evidenceId: string;
  evidenceHash: string; // SHA-256 of the intake image
  currentHash: string; // SHA-256 of canonical payload
  signatureHex: string; // ECDSA P-256 signature in hex
}

export interface EvidenceItem {
  id: string;
  caseId: string;
  evidenceId: string;
  collectorName: string;
  collectorAgency: string;
  collectorBadge: string;
  description: string;
  timestamp: string;
  imageFileName: string;
  imageFileSize: number;
  imageMimeType: string;
  imageDataUrl: string; // Data URL for preview
  sha256Hash: string; // Web Crypto SHA-256 in hex
}

export interface ActorIdentity {
  id: string;
  name: string;
  role: string;
  agency: string;
  badgeNumber: string;
  publicKeyJwk: JsonWebKey;
  privateKeyJwk?: JsonWebKey; // Stored locally to allow signing as this actor
}

export interface BlockVerificationStatus {
  blockIndex: number;
  isValid: boolean;
  isHashValid: boolean;
  isPreviousHashValid: boolean;
  isSignatureValid: boolean;
  calculatedHash: string;
  recordedHash: string;
  expectedPreviousHash: string;
  recordedPreviousHash: string;
  errorMessages: string[];
}

export interface ChainVerificationReport {
  isChainValid: boolean;
  totalBlocks: number;
  validBlocksCount: number;
  firstBrokenBlockIndex: number | null;
  verifiedAt: string;
  blockStatuses: BlockVerificationStatus[];
  auditSummary: string;
}

export interface CaseMerkleSeal {
  merkleRoot: string;
  sealedAt: string;
  sealedBy: string;
  sealedByRole: string;
  signatureHex: string;
  evidenceCount: number;
  evidenceHashes: { evidenceId: string; sha256Hash: string; label: string }[];
}

export interface ForensicCase {
  caseId: string;
  caseTitle: string;
  createdAt: string;
  evidence: EvidenceItem;
  evidenceList?: EvidenceItem[];
  merkleSeal?: CaseMerkleSeal;
  blocks: CustodyBlock[];
}

export interface StegoPayloadData {
  caseId: string;
  evidenceId: string;
  originalImageHash: string;
  ledgerHeadHash: string;
  timestamp: string;
  signerName: string;
  signerRole: string;
  signerAgency: string;
  signerPublicKeyJwk: JsonWebKey;
}

export interface StegoPayload extends StegoPayloadData {
  signatureHex: string;
}

export interface StegoExtractionResult {
  status: 'VALID' | 'WRONG_PASSPHRASE_OR_CORRUPT' | 'NO_SEAL_FOUND';
  payload: StegoPayload | null;
  isSignatureValid?: boolean;
  isLedgerHeadMatched?: boolean;
  ledgerHeadMatchDetails?: string;
  errorMessage?: string;
}

export interface InvisibilityMetrics {
  psnr: number;
  mse: number;
  modifiedPixels: number;
  totalPixels: number;
  modifiedChannels: number;
  totalCapacityBytes: number;
  payloadSizeBytes: number;
  capacityPercentageUsed: number;
}

export interface WatermarkQualityMetrics {
  psnr: number; // in dB
  ssim: number; // 0 to 1
  mse: number;
  strength: number;
}

export interface AttackResult {
  id: string;
  name: string;
  description: string;
  matchedBits: number;
  totalBits: number;
  bitMatchPercent: number;
  confidenceScore: number;
  passed: boolean;
  thumbnailDataUrl?: string;
}

export interface WatermarkExtractionResult {
  status: 'DETECTED' | 'WEAK' | 'NOT_FOUND';
  extractedHex: string;
  expectedHex: string;
  matchedBits: number;
  totalBits: number;
  bitMatchPercent: number;
  confidenceScore: number;
  details: string;
}

export type VerificationCheckStatus = 'PASS' | 'FAIL' | 'INCONCLUSIVE' | 'NA';

export interface VerificationCheckItem {
  id: string;
  name: string;
  status: VerificationCheckStatus;
  summary: string;
  details: string;
  weight: number;
  score: number; // 0 to 100
}

export type ForensicVerdict = 'AUTHENTIC' | 'TAMPERED' | 'INCONCLUSIVE';

export interface SuspiciousRegion {
  id: string;
  x: number;
  y: number;
  width: number;
  height: number;
  suspicionScore: number; // 0 to 1
  label: string;
}

export interface TamperHeatmapData {
  gridWidth: number;
  gridHeight: number;
  blockSize: number;
  scores: number[][]; // normalized 0 to 1
  suspiciousRegions: SuspiciousRegion[];
  heatmapDataUrl: string;
  comparisonMethod: 'BLOCK_DIFF_SSIM' | 'DCT_REGIONAL_DEGRADATION';
}

export interface ComprehensiveVerificationReport {
  verdict: ForensicVerdict;
  confidencePercent: number;
  verifiedAt: string;
  suspectImageSha256: string;
  checks: {
    fileHash: VerificationCheckItem;
    hiddenSeal: VerificationCheckItem;
    signature: VerificationCheckItem;
    ledgerIntegrity: VerificationCheckItem;
    robustWatermark: VerificationCheckItem;
  };
  reasons: string[];
  heatmap: TamperHeatmapData | null;
  recoveredPayload: StegoPayload | null;
  evidenceSource: 'LEDGER_LINKED' | 'SELF_VERIFYING_EMBEDDED';
  explanationDetails: string[];
}

export interface ReportOptions {
  includeEvidenceDetails: boolean;
  includeChainOfCustody: boolean;
  includeIntegrityChecks: boolean;
  includeVerdict: boolean;
  includeHeatmap: boolean;
  includeMethodology: boolean;
  includeSignatures: boolean;
  includeMerkleTree?: boolean;
  includeAiExplanation?: boolean;
  aiExplanationText?: string;
  language: 'en' | 'mr';
  investigatorName: string;
  investigatorOrg: string;
  notes: string;
}

export interface CompactReportQrPayload {
  reportId: string;
  caseId: string;
  evidenceId: string;
  evidenceHash: string;
  ledgerHeadHash: string;
  reportHash: string;
  verdict: ForensicVerdict;
  generatedAt: string;
  merkleRoot?: string;
}

export interface GeneratedReportData {
  reportId: string;
  generatedAt: string;
  caseId: string;
  evidenceId: string;
  investigatorName: string;
  investigatorOrg: string;
  options: ReportOptions;
  reportHash: string;
  reportSignatureHex: string;
  qrPayload: CompactReportQrPayload;
  qrDataUrl: string;
}

// ============================================================================
// MERKLE TREE CASE SEAL TYPES
// ============================================================================
export interface MerkleProofStep {
  siblingHash: string;
  position: 'left' | 'right';
}

export interface MerkleProof {
  evidenceId: string;
  label: string;
  leafHash: string;
  rootHash: string;
  proof: MerkleProofStep[];
  isVerified: boolean;
}

export interface MerkleNodeInfo {
  id: string;
  hash: string;
  level: number;
  index: number;
  isLeaf: boolean;
  label?: string;
  evidenceId?: string;
  leftChildId?: string;
  rightChildId?: string;
}

export interface MerkleTreeData {
  root: string;
  leaves: string[];
  levels: string[][];
  leafMap: Record<string, { evidenceId: string; label: string; hash: string }>;
  nodes: MerkleNodeInfo[];
}

// ============================================================================
// ROLE-BASED ACCESS CONTROL (RBAC) TYPES
// ============================================================================
export type UserRole = 'COLLECTOR' | 'ANALYST' | 'JUDGE';

export interface UserProfile {
  id: string;
  username: string;
  name: string;
  role: UserRole;
  title: string;
  agency: string;
  badge: string;
  avatarColor: string;
  publicKeyJwk: JsonWebKey;
  privateKeyJwk: JsonWebKey;
}

export interface AuditLogFilter {
  user: string;
  role: string;
  eventType: string;
  searchTerm: string;
}

// ============================================================================
// AI FORENSIC ASSISTANT TYPES
// ============================================================================
export interface AiChatMessage {
  id: string;
  role: 'user' | 'assistant';
  text: string;
  timestamp: string;
  isAiGenerated: boolean;
  isFallback?: boolean;
}

export interface StructuredForensicDataForAi {
  caseId: string;
  evidenceId: string;
  suspectImageSha256: string;
  verdict: ForensicVerdict;
  confidencePercent: number;
  checks: {
    fileHash: { status: VerificationCheckStatus; reason: string };
    hiddenSeal: { status: VerificationCheckStatus; reason: string };
    signature: { status: VerificationCheckStatus; reason: string };
    ledgerIntegrity: { status: VerificationCheckStatus; reason: string };
    robustWatermark: { status: VerificationCheckStatus; reason: string };
  };
  reasons: string[];
  suspiciousRegions: Array<{
    label: string;
    x: number;
    y: number;
    width: number;
    height: number;
    anomalyScore: number;
  }>;
  attackType?: string | null;
  ledgerSummary: {
    totalBlocks: number;
    lastEvent: CustodyEventType;
    isChainValid: boolean;
  };
  merkleSeal?: {
    isSealed: boolean;
    merkleRoot?: string;
    evidenceCount?: number;
  };
}




