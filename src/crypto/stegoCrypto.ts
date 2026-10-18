/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  StegoPayload,
  StegoPayloadData,
  ActorIdentity,
  InvisibilityMetrics,
} from '../types/forensics';
import {
  importECDSAPrivateKey,
  importECDSAPublicKey,
  signCanonicalPayload,
  bufferToHex,
  hexToBuffer,
} from './webCrypto';

const STEGO_MAGIC = new Uint8Array([0x53, 0x45, 0x41, 0x4c]); // "SEAL"

/**
 * Returns deterministic canonical string representation of StegoPayloadData for ECDSA signing.
 */
export function getCanonicalStegoPayload(data: StegoPayloadData): string {
  const canonicalObj = {
    caseId: data.caseId,
    evidenceId: data.evidenceId,
    ledgerHeadHash: data.ledgerHeadHash,
    originalImageHash: data.originalImageHash,
    signerAgency: data.signerAgency,
    signerName: data.signerName,
    signerRole: data.signerRole,
    timestamp: data.timestamp,
  };
  return JSON.stringify(canonicalObj);
}

/**
 * Creates and digitally signs a StegoPayload using the actor's ECDSA P-256 private key.
 */
export async function createSignedStegoPayload(params: {
  caseId: string;
  evidenceId: string;
  originalImageHash: string;
  ledgerHeadHash: string;
  actor: ActorIdentity;
  timestamp?: string;
}): Promise<StegoPayload> {
  const {
    caseId,
    evidenceId,
    originalImageHash,
    ledgerHeadHash,
    actor,
    timestamp = new Date().toISOString(),
  } = params;

  if (!actor.privateKeyJwk) {
    throw new Error(`Actor ${actor.name} lacks an ECDSA private key for signing.`);
  }

  const payloadData: StegoPayloadData = {
    caseId,
    evidenceId,
    originalImageHash,
    ledgerHeadHash,
    timestamp,
    signerName: actor.name,
    signerRole: actor.role,
    signerAgency: actor.agency,
    signerPublicKeyJwk: actor.publicKeyJwk,
  };

  const canonicalString = getCanonicalStegoPayload(payloadData);
  const privateKey = await importECDSAPrivateKey(actor.privateKeyJwk);
  const signatureHex = await signCanonicalPayload(privateKey, canonicalString);

  return {
    ...payloadData,
    signatureHex,
  };
}

/**
 * Verifies the ECDSA P-256 digital signature of an extracted StegoPayload.
 */
export async function verifyStegoSignature(payload: StegoPayload): Promise<boolean> {
  try {
    const canonicalString = getCanonicalStegoPayload(payload);
    const publicKey = await importECDSAPublicKey(payload.signerPublicKeyJwk);
    const enc = new TextEncoder();
    const dataBuffer = enc.encode(canonicalString);
    const signatureBuffer = hexToBuffer(payload.signatureHex);

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
    console.error('Stego ECDSA verification error:', err);
    return false;
  }
}

/**
 * Encrypts JSON payload string using PBKDF2 (100,000 iterations) + AES-GCM 256.
 * Returns Uint8Array: [MAGIC (4b)] + [SALT (16b)] + [IV (12b)] + [CIPHERTEXT (variable)].
 */
export async function encryptPayloadAESGCM(
  payloadJson: string,
  passphrase: string
): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const rawPassphrase = enc.encode(passphrase);
  const payloadBytes = enc.encode(payloadJson);

  // 1. Generate 16 bytes of random salt
  const salt = window.crypto.getRandomValues(new Uint8Array(16));

  // 2. Import raw passphrase for PBKDF2
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    rawPassphrase,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  // 3. Derive 256-bit AES-GCM key with 100,000 iterations of SHA-256
  const aesKey = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  // 4. Generate 12 bytes of random IV for AES-GCM
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  // 5. Encrypt with AES-GCM (produces ciphertext + 16-byte authentication tag)
  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    aesKey,
    payloadBytes
  );

  const ciphertext = new Uint8Array(ciphertextBuffer);

  // 6. Combine: MAGIC (4) + SALT (16) + IV (12) + CIPHERTEXT
  const totalLength = 4 + 16 + 12 + ciphertext.length;
  const combined = new Uint8Array(totalLength);
  combined.set(STEGO_MAGIC, 0);
  combined.set(salt, 4);
  combined.set(iv, 20);
  combined.set(ciphertext, 32);

  return combined;
}

/**
 * Decrypts encrypted byte packet using passphrase via PBKDF2 + AES-GCM.
 */
export async function decryptPayloadAESGCM(
  encryptedPacket: Uint8Array,
  passphrase: string
): Promise<string> {
  // Check minimal length: 4 (magic) + 16 (salt) + 12 (iv) + 16 (gcm tag) = 48 bytes
  if (encryptedPacket.length < 48) {
    throw new Error('CORRUPTED_LENGTH');
  }

  // Verify magic header
  for (let i = 0; i < 4; i++) {
    if (encryptedPacket[i] !== STEGO_MAGIC[i]) {
      throw new Error('NO_SEAL_MAGIC');
    }
  }

  const salt = encryptedPacket.slice(4, 20);
  const iv = encryptedPacket.slice(20, 32);
  const ciphertext = encryptedPacket.slice(32);

  const enc = new TextEncoder();
  const rawPassphrase = enc.encode(passphrase);

  // Import key material
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    rawPassphrase,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  // Derive AES-GCM key
  const aesKey = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  try {
    // Decrypt with AES-GCM (verifies authentication tag automatically)
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
      },
      aesKey,
      ciphertext
    );

    return new TextDecoder().decode(decryptedBuffer);
  } catch (err) {
    // In Web Crypto, failed authentication in AES-GCM throws OperationError
    throw new Error('WRONG_PASSPHRASE_OR_AUTH_FAIL');
  }
}

/**
 * Calculates maximum capacity in bytes for LSB embedding in R, G, B channels.
 */
export function calculateImageLSBCapacityBytes(width: number, height: number): number {
  const totalRgbChannels = width * height * 3;
  // 32-bit header is 4 bytes
  if (totalRgbChannels <= 32) return 0;
  return Math.floor((totalRgbChannels - 32) / 8);
}

/**
 * Embeds bytes into the Least Significant Bit (LSB) of R, G, B channels of an ImageData.
 * Skips the Alpha channel (idx % 4 === 3).
 * Prepends a 32-bit big-endian length integer.
 */
export function embedBytesLSB(
  originalImageData: ImageData,
  payloadBytes: Uint8Array
): {
  sealedImageData: ImageData;
  modifiedPixels: number;
  modifiedChannels: number;
  totalCapacityBytes: number;
} {
  const width = originalImageData.width;
  const height = originalImageData.height;
  const totalCapacityBytes = calculateImageLSBCapacityBytes(width, height);

  if (payloadBytes.length > totalCapacityBytes) {
    throw new Error(
      `Payload size (${payloadBytes.length} bytes) exceeds maximum image capacity (${totalCapacityBytes} bytes).`
    );
  }

  // Clone pixel array
  const sealedData = new Uint8ClampedArray(originalImageData.data);
  const totalPixels = width * height;

  // Total bits to write: 32 bits for length + payloadBytes.length * 8
  const payloadLength = payloadBytes.length;
  const totalBitsToWrite = 32 + payloadLength * 8;

  let bitIndex = 0;
  let modifiedChannels = 0;
  const modifiedPixelIndices = new Set<number>();

  for (let pixelIdx = 0; pixelIdx < totalPixels && bitIndex < totalBitsToWrite; pixelIdx++) {
    const baseOffset = pixelIdx * 4;

    // Iterate through R (0), G (1), B (2) channels; skip Alpha (3)
    for (let c = 0; c < 3 && bitIndex < totalBitsToWrite; c++) {
      const channelOffset = baseOffset + c;
      const originalVal = sealedData[channelOffset];

      // Determine bit value
      let bitValue = 0;
      if (bitIndex < 32) {
        // 32-bit big-endian length header
        bitValue = (payloadLength >>> (31 - bitIndex)) & 1;
      } else {
        // Payload bits
        const byteOffset = Math.floor((bitIndex - 32) / 8);
        const bitInByte = 7 - ((bitIndex - 32) % 8);
        bitValue = (payloadBytes[byteOffset] >>> bitInByte) & 1;
      }

      const newVal = (originalVal & 0xfe) | bitValue;
      if (newVal !== originalVal) {
        sealedData[channelOffset] = newVal;
        modifiedChannels++;
        modifiedPixelIndices.add(pixelIdx);
      }

      bitIndex++;
    }
  }

  const sealedImageData = new ImageData(sealedData, width, height);

  return {
    sealedImageData,
    modifiedPixels: modifiedPixelIndices.size,
    modifiedChannels,
    totalCapacityBytes,
  };
}

/**
 * Extracts embedded bytes from the LSBs of R, G, B channels of an ImageData.
 * Returns null if no valid length header / magic header found.
 */
export function extractBytesLSB(imageData: ImageData): Uint8Array | null {
  const width = imageData.width;
  const height = imageData.height;
  const data = imageData.data;
  const totalPixels = width * height;
  const maxPossibleBytes = calculateImageLSBCapacityBytes(width, height);

  if (maxPossibleBytes < 48) {
    return null;
  }

  // 1. Read first 32 bits for length header
  let lengthHeader = 0;
  let bitIndex = 0;
  let currentPixel = 0;
  let currentChannel = 0;

  while (bitIndex < 32 && currentPixel < totalPixels) {
    const channelOffset = currentPixel * 4 + currentChannel;
    const bit = data[channelOffset] & 1;
    lengthHeader = (lengthHeader << 1) | bit;

    bitIndex++;
    currentChannel++;
    if (currentChannel === 3) {
      currentChannel = 0;
      currentPixel++;
    }
  }

  // Treat as unsigned 32-bit
  const payloadByteLength = lengthHeader >>> 0;

  // Sanity check: must be at least 48 bytes (magic + salt + iv + gcm tag) and not exceed image capacity
  if (payloadByteLength < 48 || payloadByteLength > maxPossibleBytes) {
    return null;
  }

  // 2. Read payload bytes
  const payload = new Uint8Array(payloadByteLength);
  const totalPayloadBits = payloadByteLength * 8;
  let payloadBitIndex = 0;

  while (payloadBitIndex < totalPayloadBits && currentPixel < totalPixels) {
    const channelOffset = currentPixel * 4 + currentChannel;
    const bit = data[channelOffset] & 1;

    const byteIdx = Math.floor(payloadBitIndex / 8);
    const bitInByte = 7 - (payloadBitIndex % 8);

    if (bit === 1) {
      payload[byteIdx] |= 1 << bitInByte;
    }

    payloadBitIndex++;
    currentChannel++;
    if (currentChannel === 3) {
      currentChannel = 0;
      currentPixel++;
    }
  }

  if (payloadBitIndex < totalPayloadBits) {
    return null;
  }

  // Check magic marker ("SEAL")
  if (
    payload[0] !== STEGO_MAGIC[0] ||
    payload[1] !== STEGO_MAGIC[1] ||
    payload[2] !== STEGO_MAGIC[2] ||
    payload[3] !== STEGO_MAGIC[3]
  ) {
    return null;
  }

  return payload;
}

/**
 * Calculates Peak Signal-to-Noise Ratio (PSNR), Mean Squared Error (MSE),
 * and generates a x50 amplified visual difference ImageData.
 */
export function calculatePSNRAndDiff(
  originalImageData: ImageData,
  sealedImageData: ImageData,
  payloadSizeBytes: number
): {
  metrics: InvisibilityMetrics;
  diffImageData: ImageData;
} {
  const width = originalImageData.width;
  const height = originalImageData.height;
  const origData = originalImageData.data;
  const sealData = sealedImageData.data;
  const totalPixels = width * height;

  const diffData = new Uint8ClampedArray(totalPixels * 4);
  let sumSquaredError = 0;
  let modifiedPixelsCount = 0;
  let modifiedChannelsCount = 0;

  for (let p = 0; p < totalPixels; p++) {
    const offset = p * 4;
    let pixelDiff = false;

    // Process R, G, B channels
    for (let c = 0; c < 3; c++) {
      const idx = offset + c;
      const d = Math.abs(origData[idx] - sealData[idx]);

      if (d !== 0) {
        pixelDiff = true;
        modifiedChannelsCount++;
        sumSquaredError += d * d;
        // Amplify difference by 50x for human visibility on diff map
        diffData[idx] = Math.min(255, d * 50);
      } else {
        diffData[idx] = 0;
      }
    }

    if (pixelDiff) {
      modifiedPixelsCount++;
    }

    // Alpha channel for diff map: opaque 255
    diffData[offset + 3] = 255;
  }

  // Mean Squared Error (over R, G, B channels = 3 * totalPixels)
  const mse = sumSquaredError / (3 * totalPixels);

  // Peak Signal-to-Noise Ratio
  let psnr = 100; // default for identical images
  if (mse > 0) {
    psnr = 10 * Math.log10((255 * 255) / mse);
  }

  const totalCapacityBytes = calculateImageLSBCapacityBytes(width, height);
  const capacityPercentageUsed =
    totalCapacityBytes > 0 ? (payloadSizeBytes / totalCapacityBytes) * 100 : 0;

  const metrics: InvisibilityMetrics = {
    psnr: Number(psnr.toFixed(2)),
    mse: Number(mse.toFixed(6)),
    modifiedPixels: modifiedPixelsCount,
    totalPixels,
    modifiedChannels: modifiedChannelsCount,
    totalCapacityBytes,
    payloadSizeBytes,
    capacityPercentageUsed: Number(capacityPercentageUsed.toFixed(2)),
  };

  const diffImageData = new ImageData(diffData, width, height);

  return { metrics, diffImageData };
}

/**
 * Loads an image from dataUrl onto an HTML Canvas and extracts its ImageData.
 */
export function loadImageDataFromUrl(
  dataUrl: string
): Promise<{ imageData: ImageData; width: number; height: number }> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.crossOrigin = 'anonymous';
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      if (!ctx) {
        reject(new Error('Failed to create canvas 2D context'));
        return;
      }
      ctx.drawImage(img, 0, 0);
      const imageData = ctx.getImageData(0, 0, img.width, img.height);
      resolve({ imageData, width: img.width, height: img.height });
    };
    img.onerror = () => reject(new Error('Failed to load image asset'));
    img.src = dataUrl;
  });
}

/**
 * Converts ImageData to a lossless PNG Data URL.
 */
export function imageDataToPngDataUrl(imageData: ImageData): string {
  const canvas = document.createElement('canvas');
  canvas.width = imageData.width;
  canvas.height = imageData.height;
  const ctx = canvas.getContext('2d');
  if (!ctx) {
    throw new Error('Canvas 2D context unavailable');
  }
  ctx.putImageData(imageData, 0, 0);
  return canvas.toDataURL('image/png');
}
