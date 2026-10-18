/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  CustodyBlock,
  BlockVerificationStatus,
  ChainVerificationReport,
  ActorIdentity,
} from '../types/forensics';

export const GENESIS_PREVIOUS_HASH =
  '0000000000000000000000000000000000000000000000000000000000000000';

/**
 * Converts ArrayBuffer to lowercase hex string.
 */
export function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Converts hex string to Uint8Array.
 */
export function hexToBuffer(hex: string): Uint8Array {
  const cleanHex = hex.replace(/[^0-9a-fA-F]/g, '');
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Computes real SHA-256 hash using the Web Crypto API.
 */
export async function computeSHA256(data: ArrayBuffer | Uint8Array | string): Promise<string> {
  let buffer: ArrayBuffer;
  if (typeof data === 'string') {
    buffer = new TextEncoder().encode(data).buffer;
  } else if (data instanceof Uint8Array) {
    // Slice ensures we have an exact ArrayBuffer
    buffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  } else {
    buffer = data;
  }

  const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);
  return bufferToHex(hashBuffer);
}

/**
 * Computes SHA-256 of a File or Blob using Web Crypto API.
 */
export async function computeFileSHA256(file: File | Blob): Promise<string> {
  const arrayBuffer = await file.arrayBuffer();
  return computeSHA256(arrayBuffer);
}

/**
 * Generates an ECDSA key pair (P-256 curve) using Web Crypto API.
 */
export async function generateECDSAKeyPair(): Promise<{
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  publicKeyJwk: JsonWebKey;
  privateKeyJwk: JsonWebKey;
  fingerprint: string;
}> {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify']
  );

  const publicKeyJwk = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const privateKeyJwk = await window.crypto.subtle.exportKey('jwk', keyPair.privateKey);

  // Derive public key fingerprint from SHA-256 of sorted public key JWK
  const pubKeyString = JSON.stringify({
    crv: publicKeyJwk.crv,
    kty: publicKeyJwk.kty,
    x: publicKeyJwk.x,
    y: publicKeyJwk.y,
  });
  const hash = await computeSHA256(pubKeyString);
  const fingerprint = `ECDSA-${hash.substring(0, 16).toUpperCase()}`;

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    publicKeyJwk,
    privateKeyJwk,
    fingerprint,
  };
}

/**
 * Imports ECDSA public key from JWK for verification.
 */
export async function importECDSAPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return window.crypto.subtle.importKey(
    'jwk',
    {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      y: jwk.y,
      ext: true,
    },
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['verify']
  );
}

/**
 * Imports ECDSA private key from JWK for signing.
 */
export async function importECDSAPrivateKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return window.crypto.subtle.importKey(
    'jwk',
    {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      y: jwk.y,
      d: jwk.d,
      ext: true,
    },
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign']
  );
}

/**
 * Produces a canonical string representation of block data.
 * Must be deterministic so hashing and signature verification are consistent.
 */
export function getCanonicalBlockPayload(
  block: Omit<CustodyBlock, 'currentHash' | 'signatureHex'>
): string {
  // Explicit ordered structure ensures deterministic stringification
  const canonicalObj = {
    blockIndex: block.blockIndex,
    previousHash: block.previousHash,
    timestamp: block.timestamp,
    eventType: block.eventType,
    actorName: block.actorName,
    actorRole: block.actorRole,
    actorAgency: block.actorAgency,
    actorPublicKeyFingerprint: block.actorPublicKeyFingerprint,
    evidenceId: block.evidenceId,
    evidenceHash: block.evidenceHash,
    details: {
      action: block.details.action,
      departmentOrAgency: block.details.departmentOrAgency || '',
      facilityLocation: block.details.facilityLocation || '',
      toolOrMethodUsed: block.details.toolOrMethodUsed || '',
      notes: block.details.notes,
      recipientName: block.details.recipientName || '',
      recipientRole: block.details.recipientRole || '',
      authorizationReference: block.details.authorizationReference || '',
    },
  };
  return JSON.stringify(canonicalObj);
}

/**
 * Signs canonical payload with ECDSA private key.
 */
export async function signCanonicalPayload(
  privateKey: CryptoKey,
  canonicalPayload: string
): Promise<string> {
  const enc = new TextEncoder();
  const dataBuffer = enc.encode(canonicalPayload);
  const signatureBuffer = await window.crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: { name: 'SHA-256' },
    },
    privateKey,
    dataBuffer
  );
  return bufferToHex(signatureBuffer);
}

/**
 * Convenience helper to sign a string using an ECDSA private key in JWK format.
 */
export async function signDataWithKey(
  data: string,
  privateKeyJwk: JsonWebKey
): Promise<string> {
  const privateKey = await importECDSAPrivateKey(privateKeyJwk);
  return signCanonicalPayload(privateKey, data);
}

/**
 * Verifies ECDSA signature of canonical payload against public key JWK.
 */
export async function verifyCanonicalSignature(
  publicKeyJwk: JsonWebKey,
  canonicalPayload: string,
  signatureHex: string
): Promise<boolean> {
  try {
    const publicKey = await importECDSAPublicKey(publicKeyJwk);
    const enc = new TextEncoder();
    const dataBuffer = enc.encode(canonicalPayload);
    const signatureBuffer = hexToBuffer(signatureHex);
    return await window.crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' },
      },
      publicKey,
      signatureBuffer as unknown as BufferSource,
      dataBuffer
    );
  } catch (err) {
    console.error('ECDSA signature verification error:', err);
    return false;
  }
}

/**
 * Computes block hash from its canonical payload string.
 */
export async function computeBlockHash(canonicalPayload: string): Promise<string> {
  return computeSHA256(canonicalPayload);
}

/**
 * Creates a fully sealed, cryptographically signed CustodyBlock.
 */
export async function createSignedBlock(params: {
  blockIndex: number;
  previousHash: string;
  eventType: CustodyBlock['eventType'];
  actor: ActorIdentity;
  details: CustodyBlock['details'];
  evidenceId: string;
  evidenceHash: string;
  timestamp?: string;
}): Promise<CustodyBlock> {
  const {
    blockIndex,
    previousHash,
    eventType,
    actor,
    details,
    evidenceId,
    evidenceHash,
    timestamp = new Date().toISOString(),
  } = params;

  if (!actor.privateKeyJwk) {
    throw new Error(`Actor ${actor.name} does not have a private key available to sign.`);
  }

  // Derive actor fingerprint
  const pubKeyString = JSON.stringify({
    crv: actor.publicKeyJwk.crv,
    kty: actor.publicKeyJwk.kty,
    x: actor.publicKeyJwk.x,
    y: actor.publicKeyJwk.y,
  });
  const pubHash = await computeSHA256(pubKeyString);
  const fingerprint = `ECDSA-${pubHash.substring(0, 16).toUpperCase()}`;

  const partialBlock: Omit<CustodyBlock, 'currentHash' | 'signatureHex'> = {
    blockIndex,
    previousHash,
    timestamp,
    eventType,
    actorName: actor.name,
    actorRole: actor.role,
    actorAgency: actor.agency,
    actorPublicKeyJwk: actor.publicKeyJwk,
    actorPublicKeyFingerprint: fingerprint,
    details,
    evidenceId,
    evidenceHash,
  };

  const canonicalPayload = getCanonicalBlockPayload(partialBlock);
  const currentHash = await computeBlockHash(canonicalPayload);

  // Sign with actor's ECDSA private key
  const privateKey = await importECDSAPrivateKey(actor.privateKeyJwk);
  const signatureHex = await signCanonicalPayload(privateKey, canonicalPayload);

  return {
    ...partialBlock,
    currentHash,
    signatureHex,
  };
}

/**
 * Verifies the entire chain of custody blocks.
 * If block i fails verification, that block and ALL subsequent blocks are marked as broken.
 */
export async function verifyChainIntegrity(
  blocks: CustodyBlock[]
): Promise<ChainVerificationReport> {
  const verifiedAt = new Date().toISOString();
  if (!blocks || blocks.length === 0) {
    return {
      isChainValid: true,
      totalBlocks: 0,
      validBlocksCount: 0,
      firstBrokenBlockIndex: null,
      verifiedAt,
      blockStatuses: [],
      auditSummary: 'Ledger is empty. No blocks to verify.',
    };
  }

  const blockStatuses: BlockVerificationStatus[] = [];
  let firstBrokenIndex: number | null = null;

  for (let i = 0; i < blocks.length; i++) {
    const block = blocks[i];
    const errors: string[] = [];

    // If chain was already broken by an earlier block, this block is automatically broken
    if (firstBrokenIndex !== null) {
      blockStatuses.push({
        blockIndex: block.blockIndex,
        isValid: false,
        isHashValid: false,
        isPreviousHashValid: false,
        isSignatureValid: false,
        calculatedHash: 'CASCADE_FAILURE',
        recordedHash: block.currentHash,
        expectedPreviousHash: blocks[i - 1]?.currentHash || '',
        recordedPreviousHash: block.previousHash,
        errorMessages: [
          `Chain continuity broken upstream at Block #${firstBrokenIndex}. Cryptographic trust invalidated.`,
        ],
      });
      continue;
    }

    // 1. Check previous hash link
    let expectedPrevHash = GENESIS_PREVIOUS_HASH;
    let isPrevHashValid = true;
    if (i > 0) {
      expectedPrevHash = blocks[i - 1].currentHash;
      if (block.previousHash.toLowerCase() !== expectedPrevHash.toLowerCase()) {
        isPrevHashValid = false;
        errors.push(
          `Previous hash pointer mismatch! Recorded: ${block.previousHash.substring(0, 16)}... Expected: ${expectedPrevHash.substring(0, 16)}...`
        );
      }
    } else {
      // Genesis block
      if (block.previousHash !== GENESIS_PREVIOUS_HASH) {
        isPrevHashValid = false;
        errors.push(
          `Genesis block previous hash is invalid. Must equal 64 zeroes (${GENESIS_PREVIOUS_HASH.substring(0, 16)}...).`
        );
      }
    }

    // 2. Recompute current block hash from canonical payload
    const canonicalPayload = getCanonicalBlockPayload(block);
    const calculatedHash = await computeBlockHash(canonicalPayload);
    const isHashValid = calculatedHash.toLowerCase() === block.currentHash.toLowerCase();

    if (!isHashValid) {
      errors.push(
        `Block hash mismatch! Content recalculation yields ${calculatedHash.substring(0, 16)}..., but ledger records ${block.currentHash.substring(0, 16)}...`
      );
    }

    // 3. Verify ECDSA signature
    const isSigValid = await verifyCanonicalSignature(
      block.actorPublicKeyJwk,
      canonicalPayload,
      block.signatureHex
    );

    if (!isSigValid) {
      errors.push(
        `ECDSA digital signature verification failed! The block content does not match the cryptographic signature of ${block.actorName}.`
      );
    }

    const isThisBlockValid = isPrevHashValid && isHashValid && isSigValid;

    if (!isThisBlockValid) {
      firstBrokenIndex = i;
    }

    blockStatuses.push({
      blockIndex: block.blockIndex,
      isValid: isThisBlockValid,
      isHashValid,
      isPreviousHashValid: isPrevHashValid,
      isSignatureValid: isSigValid,
      calculatedHash,
      recordedHash: block.currentHash,
      expectedPreviousHash: expectedPrevHash,
      recordedPreviousHash: block.previousHash,
      errorMessages: errors,
    });
  }

  const isChainValid = firstBrokenIndex === null;
  const validBlocksCount = blockStatuses.filter((s) => s.isValid).length;

  let auditSummary = '';
  if (firstBrokenIndex === null) {
    auditSummary = `All ${blocks.length} block(s) cryptographically verified. Hash pointers continuous, hashes intact, and ECDSA P-256 digital signatures authenticated.`;
  } else {
    auditSummary = `INTEGRITY VIOLATION: Cryptographic chain compromised at Block #${firstBrokenIndex}. Block #${firstBrokenIndex} and all ${blocks.length - firstBrokenIndex} subsequent blocks are invalidated.`;
  }

  return {
    isChainValid,
    totalBlocks: blocks.length,
    validBlocksCount,
    firstBrokenBlockIndex: firstBrokenIndex,
    verifiedAt,
    blockStatuses,
    auditSummary,
  };
}
