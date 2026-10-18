/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  ForensicCase,
  ActorIdentity,
  EvidenceItem,
  CustodyBlock,
} from '../types/forensics';
import {
  generateECDSAKeyPair,
  computeSHA256,
  createSignedBlock,
  GENESIS_PREVIOUS_HASH,
} from '../crypto/webCrypto';
import { generateSampleForensicImage } from '../utils/sampleEvidence';

const STORAGE_KEYS = {
  ACTIVE_CASE: 'sealchain_active_case_v1',
  ACTORS: 'sealchain_actors_v1',
  BACKUP_CASE: 'sealchain_backup_case_v1',
};

/**
 * Generates default digital forensics officers with real ECDSA keypairs.
 */
export async function generateDefaultActors(): Promise<ActorIdentity[]> {
  const actorConfigs = [
    {
      id: 'actor-rostova',
      name: 'Det. Elena Rostova',
      role: 'Lead Cyber Forensics Investigator',
      agency: 'State Digital Crimes Division',
      badgeNumber: 'CF-409',
    },
    {
      id: 'actor-vance',
      name: 'Dr. Marcus Vance',
      role: 'Hardware Forensics Specialist',
      agency: 'Regional Cyber Forensics Laboratory',
      badgeNumber: 'LAB-882',
    },
    {
      id: 'actor-jenkins',
      name: 'Sarah Jenkins',
      role: 'Chief Evidence Custodian',
      agency: 'Secure Physical & Digital Evidence Vault',
      badgeNumber: 'VAULT-019',
    },
    {
      id: 'actor-miller',
      name: 'Agent David Miller',
      role: 'Federal Cyber Task Force Agent',
      agency: 'National Cyber Security Agency',
      badgeNumber: 'NCSA-104',
    },
  ];

  const actors: ActorIdentity[] = [];
  for (const config of actorConfigs) {
    const keyPair = await generateECDSAKeyPair();
    actors.push({
      ...config,
      publicKeyJwk: keyPair.publicKeyJwk,
      privateKeyJwk: keyPair.privateKeyJwk,
    });
  }

  return actors;
}

/**
 * Initializes a realistic demonstration case with real cryptographic hashes and signatures.
 */
export async function initializeSeedCase(actors: ActorIdentity[]): Promise<ForensicCase> {
  const sample = generateSampleForensicImage();
  const imageHash = await computeSHA256(await sample.blob.arrayBuffer());

  const evidence: EvidenceItem = {
    id: 'evd-001-a',
    caseId: 'CAS-2026-9812',
    evidenceId: 'EVD-001-A',
    collectorName: actors[0].name,
    collectorAgency: actors[0].agency,
    collectorBadge: actors[0].badgeNumber,
    description: 'Seized Samsung 990 Pro 2TB M.2 NVMe SSD drive recovered from laboratory workstation B-4 during court-authorized search.',
    timestamp: '2026-10-18T06:14:00.000Z',
    imageFileName: sample.fileName,
    imageFileSize: sample.fileSize,
    imageMimeType: sample.mimeType,
    imageDataUrl: sample.dataUrl,
    sha256Hash: imageHash,
  };

  // Block #0 - Genesis (COLLECTED)
  const block0 = await createSignedBlock({
    blockIndex: 0,
    previousHash: GENESIS_PREVIOUS_HASH,
    eventType: 'COLLECTED',
    actor: actors[0],
    details: {
      action: 'Seized physical storage media at primary search location',
      departmentOrAgency: actors[0].agency,
      facilityLocation: 'Laboratory Workstation B-4, Building 3',
      toolOrMethodUsed: 'Static-shielded anti-static evidence pouch #AS-8812',
      notes: 'Drive detached from workstation motherboard; placed into Faraday shielding bag with tamper-evident seal #TE-9901.',
      authorizationReference: 'Search Warrant #SW-2026-118-B',
    },
    evidenceId: evidence.evidenceId,
    evidenceHash: evidence.sha256Hash,
    timestamp: '2026-10-18T06:18:22.000Z',
  });

  // Block #1 - TRANSFERRED
  const block1 = await createSignedBlock({
    blockIndex: 1,
    previousHash: block0.currentHash,
    eventType: 'TRANSFERRED',
    actor: actors[0],
    details: {
      action: 'Chain of custody transport transfer to Regional Cyber Forensics Lab',
      departmentOrAgency: 'Secure Evidence Transport Unit',
      facilityLocation: 'Regional Cyber Forensics Laboratory - Intake Bay 2',
      toolOrMethodUsed: 'Armed courier lockbox with GPS telemetry tracking',
      notes: 'Transferred sealed evidence bag #TE-9901 into possession of Dr. Marcus Vance for hardware imaging.',
      recipientName: actors[1].name,
      recipientRole: actors[1].role,
      authorizationReference: 'Chain Transfer Form CTF-4091',
    },
    evidenceId: evidence.evidenceId,
    evidenceHash: evidence.sha256Hash,
    timestamp: '2026-10-18T07:05:10.000Z',
  });

  // Block #2 - ANALYZED
  const block2 = await createSignedBlock({
    blockIndex: 2,
    previousHash: block1.currentHash,
    eventType: 'ANALYZED',
    actor: actors[1],
    details: {
      action: 'Hardware write-blocked forensic bit-stream physical acquisition',
      departmentOrAgency: actors[1].agency,
      facilityLocation: 'Cleanroom Forensics Station 4',
      toolOrMethodUsed: 'Tableau T8u Hardware Forensic Write-Blocker (Firmware v21.4) & FTK Imager v4.7.1',
      notes: 'Physical write-block verified via LED indicator. Bit-stream RAW DD image extracted (E01 container). Verified 0 sector write attempts.',
      recipientName: 'Dr. Marcus Vance (Forensics Lab)',
      authorizationReference: 'Forensic Work Order #FWO-9932',
    },
    evidenceId: evidence.evidenceId,
    evidenceHash: evidence.sha256Hash,
    timestamp: '2026-10-18T07:22:45.000Z',
  });

  // Block #3 - STORED
  const block3 = await createSignedBlock({
    blockIndex: 3,
    previousHash: block2.currentHash,
    eventType: 'STORED',
    actor: actors[2],
    details: {
      action: 'Long-term secure vault deposit',
      departmentOrAgency: actors[2].agency,
      facilityLocation: 'Central Evidence Vault - Sub-Level 2, Locker Unit B-14',
      toolOrMethodUsed: 'Biometric RFID High-Security Vault System (Dual-Key Custody)',
      notes: 'Physical drive re-sealed in barcode envelope #SEAL-99801. Deposited in climate-controlled locker (18°C, 40% RH).',
      recipientName: 'Sarah Jenkins (Chief Custodian)',
      authorizationReference: 'Vault Deposit Receipt #VDR-2026-081',
    },
    evidenceId: evidence.evidenceId,
    evidenceHash: evidence.sha256Hash,
    timestamp: '2026-10-18T07:41:00.000Z',
  });

  const forensicCase: ForensicCase = {
    caseId: evidence.caseId,
    caseTitle: 'Operation DeepVault - Seized Storage Media Analysis',
    createdAt: evidence.timestamp,
    evidence,
    blocks: [block0, block1, block2, block3],
  };

  return forensicCase;
}

/**
 * Loads the active case and actors from localStorage or seeds initial demo case.
 */
export async function loadOrCreateCase(): Promise<{
  caseData: ForensicCase;
  actors: ActorIdentity[];
}> {
  try {
    let actors: ActorIdentity[] = [];
    const storedActors = localStorage.getItem(STORAGE_KEYS.ACTORS);
    if (storedActors) {
      actors = JSON.parse(storedActors);
    } else {
      actors = await generateDefaultActors();
      localStorage.setItem(STORAGE_KEYS.ACTORS, JSON.stringify(actors));
    }

    const storedCase = localStorage.getItem(STORAGE_KEYS.ACTIVE_CASE);
    if (storedCase) {
      const parsedCase = JSON.parse(storedCase) as ForensicCase;
      return { caseData: parsedCase, actors };
    }

    // Seed new demo case
    const seededCase = await initializeSeedCase(actors);
    localStorage.setItem(STORAGE_KEYS.ACTIVE_CASE, JSON.stringify(seededCase));
    localStorage.setItem(STORAGE_KEYS.BACKUP_CASE, JSON.stringify(seededCase));
    return { caseData: seededCase, actors };
  } catch (err) {
    console.error('Failed to load from localStorage, initializing fresh:', err);
    const actors = await generateDefaultActors();
    const seededCase = await initializeSeedCase(actors);
    return { caseData: seededCase, actors };
  }
}

/**
 * Saves active case to localStorage.
 */
export function saveActiveCase(caseData: ForensicCase): void {
  try {
    localStorage.setItem(STORAGE_KEYS.ACTIVE_CASE, JSON.stringify(caseData));
  } catch (err) {
    console.error('Failed to save active case to localStorage:', err);
  }
}

/**
 * Saves registered actors to localStorage.
 */
export function saveActors(actors: ActorIdentity[]): void {
  try {
    localStorage.setItem(STORAGE_KEYS.ACTORS, JSON.stringify(actors));
  } catch (err) {
    console.error('Failed to save actors to localStorage:', err);
  }
}

/**
 * Restores the backup/original state before tampering.
 */
export function restoreBackupCase(): ForensicCase | null {
  try {
    const backup = localStorage.getItem(STORAGE_KEYS.BACKUP_CASE);
    if (backup) {
      const parsed = JSON.parse(backup) as ForensicCase;
      saveActiveCase(parsed);
      return parsed;
    }
  } catch (err) {
    console.error('Failed to restore backup case:', err);
  }
  return null;
}

/**
 * Saves current case as clean backup snapshot.
 */
export function setAsBackupCase(caseData: ForensicCase): void {
  try {
    localStorage.setItem(STORAGE_KEYS.BACKUP_CASE, JSON.stringify(caseData));
  } catch (err) {
    console.error('Failed to set backup case:', err);
  }
}

/**
 * Tamper helper: deliberately modifies an existing block's data without updating its hash or signature,
 * or introduces bad hash pointers to showcase cryptographic failure detection.
 */
export function applyTamperToBlock(
  caseData: ForensicCase,
  targetBlockIndex: number,
  tamperType: 'ACTOR' | 'TIMESTAMP' | 'NOTES' | 'EVIDENCE_HASH' | 'CURRENT_HASH' | 'PREVIOUS_HASH',
  tamperValue?: string
): ForensicCase {
  const updatedBlocks = caseData.blocks.map((block) => {
    if (block.blockIndex !== targetBlockIndex) {
      return { ...block };
    }

    const modified = { ...block };
    switch (tamperType) {
      case 'ACTOR':
        modified.actorName = tamperValue || 'Mallory (Unauthorized Adversary)';
        modified.actorRole = 'Unauthorized Access Actor';
        break;
      case 'TIMESTAMP':
        modified.timestamp =
          tamperValue || new Date(Date.parse(block.timestamp) - 86400000 * 3).toISOString(); // 3 days back
        break;
      case 'NOTES':
        modified.details = {
          ...modified.details,
          notes:
            tamperValue ||
            'UNAUTHORIZED ALTERATION: Evidence was unlocked and examined by unknown party without warrant authorization.',
        };
        break;
      case 'EVIDENCE_HASH':
        // Replace with altered hash
        modified.evidenceHash =
          tamperValue || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        break;
      case 'CURRENT_HASH':
        modified.currentHash =
          tamperValue || 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
        break;
      case 'PREVIOUS_HASH':
        modified.previousHash =
          tamperValue || 'c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00';
        break;
    }
    return modified;
  });

  const tamperedCase: ForensicCase = {
    ...caseData,
    blocks: updatedBlocks,
  };

  saveActiveCase(tamperedCase);
  return tamperedCase;
}

/**
 * Exports full forensic case ledger as downloadable JSON.
 */
export function exportCaseToJson(caseData: ForensicCase): void {
  const jsonString = JSON.stringify(caseData, null, 2);
  const blob = new Blob([jsonString], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  const safeCaseId = caseData.caseId.replace(/[^a-zA-Z0-9_-]/g, '_');
  a.download = `sealchain-${safeCaseId}-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Validates and imports a custody case from JSON string.
 */
export function importCaseFromJson(jsonString: string): ForensicCase {
  const parsed = JSON.parse(jsonString);

  // Validate core schema fields
  if (!parsed.caseId || !parsed.evidence || !Array.isArray(parsed.blocks)) {
    throw new Error('Invalid SealChain JSON: missing caseId, evidence, or blocks array.');
  }

  const { evidence, blocks } = parsed;
  if (!evidence.evidenceId || !evidence.sha256Hash) {
    throw new Error('Invalid Evidence structure: evidenceId or sha256Hash missing.');
  }

  for (let i = 0; i < blocks.length; i++) {
    const b = blocks[i];
    if (
      b.blockIndex === undefined ||
      !b.previousHash ||
      !b.currentHash ||
      !b.signatureHex ||
      !b.actorPublicKeyJwk
    ) {
      throw new Error(`Invalid Block at index ${i}: required cryptographic fields missing.`);
    }
  }

  const importedCase: ForensicCase = {
    caseId: String(parsed.caseId),
    caseTitle: String(parsed.caseTitle || `Case ${parsed.caseId}`),
    createdAt: String(parsed.createdAt || new Date().toISOString()),
    evidence: parsed.evidence,
    blocks: parsed.blocks,
  };

  saveActiveCase(importedCase);
  setAsBackupCase(importedCase);
  return importedCase;
}
