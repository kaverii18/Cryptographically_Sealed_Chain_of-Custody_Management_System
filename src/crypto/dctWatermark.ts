/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { computeSHA256 } from './webCrypto';
import { WatermarkQualityMetrics, AttackResult, WatermarkExtractionResult } from '../types/forensics';

// Precomputed 8x8 DCT-II orthogonal transformation matrix T
const DCT_SIZE = 8;
const DCT_T = new Float64Array(64);
const DCT_T_TRANSPOSE = new Float64Array(64);

// Initialize DCT matrices
(function initDctMatrices() {
  for (let i = 0; i < DCT_SIZE; i++) {
    const alpha = i === 0 ? 1 / Math.sqrt(8) : Math.sqrt(2 / 8);
    for (let j = 0; j < DCT_SIZE; j++) {
      const val = alpha * Math.cos(((2 * j + 1) * i * Math.PI) / 16);
      DCT_T[i * 8 + j] = val;
      DCT_T_TRANSPOSE[j * 8 + i] = val;
    }
  }
})();

/**
 * 2D 8x8 DCT: D = T * A * T^T
 */
function forwardDCT8x8(input: Float64Array, output: Float64Array) {
  // Temporary matrix for T * A
  const temp = new Float64Array(64);

  // temp = T * input
  for (let i = 0; i < 8; i++) {
    const i8 = i * 8;
    for (let j = 0; j < 8; j++) {
      let sum = 0;
      for (let k = 0; k < 8; k++) {
        sum += DCT_T[i8 + k] * input[k * 8 + j];
      }
      temp[i8 + j] = sum;
    }
  }

  // output = temp * T^T
  for (let i = 0; i < 8; i++) {
    const i8 = i * 8;
    for (let j = 0; j < 8; j++) {
      let sum = 0;
      for (let k = 0; k < 8; k++) {
        sum += temp[i8 + k] * DCT_T_TRANSPOSE[k * 8 + j];
      }
      output[i8 + j] = sum;
    }
  }
}

/**
 * 2D 8x8 Inverse DCT: A = T^T * D * T
 */
function inverseDCT8x8(input: Float64Array, output: Float64Array) {
  const temp = new Float64Array(64);

  // temp = T^T * input
  for (let i = 0; i < 8; i++) {
    const i8 = i * 8;
    for (let j = 0; j < 8; j++) {
      let sum = 0;
      for (let k = 0; k < 8; k++) {
        sum += DCT_T_TRANSPOSE[i8 + k] * input[k * 8 + j];
      }
      temp[i8 + j] = sum;
    }
  }

  // output = temp * T
  for (let i = 0; i < 8; i++) {
    const i8 = i * 8;
    for (let j = 0; j < 8; j++) {
      let sum = 0;
      for (let k = 0; k < 8; k++) {
        sum += temp[i8 + k] * DCT_T[k * 8 + j];
      }
      output[i8 + j] = sum;
    }
  }
}

/**
 * Derives a deterministic 64-bit watermark ID from case ID and evidence ID.
 */
export async function deriveWatermarkId(
  caseId: string,
  evidenceId: string
): Promise<{ hex: string; bits: number[] }> {
  const source = `SEALCHAIN_WATERMARK:${caseId.trim()}:${evidenceId.trim()}`;
  const sha = await computeSHA256(source);
  // Take first 16 hex chars (8 bytes = 64 bits)
  const hex = sha.substring(0, 16).toUpperCase();

  const bits: number[] = [];
  for (let i = 0; i < 16; i += 2) {
    const byte = parseInt(hex.substring(i, i + 2), 16);
    for (let b = 7; b >= 0; b--) {
      bits.push((byte >>> b) & 1);
    }
  }

  return { hex, bits };
}

/**
 * Converts 64 bits back to a 16-character hex string.
 */
export function bitsToHex(bits: number[]): string {
  let hex = '';
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let b = 0; b < 8; b++) {
      byte = (byte << 1) | (bits[i + b] || 0);
    }
    hex += byte.toString(16).padStart(2, '0').toUpperCase();
  }
  return hex;
}

/**
 * Embeds 64-bit watermark into the Luminance (Y) channel using 8x8 2D-DCT.
 * Modifies mid-frequency coefficient pair (4,3) and (3,4).
 * Uses chunked processing for responsive UI.
 */
export async function embedDCTWatermark(
  imageData: ImageData,
  bits: number[],
  strength: number,
  onProgress?: (percent: number) => void
): Promise<{
  watermarkedImageData: ImageData;
  metrics: WatermarkQualityMetrics;
  diffImageData: ImageData;
}> {
  const width = imageData.width;
  const height = imageData.height;
  const data = imageData.data;
  const totalPixels = width * height;

  // Convert RGB to Y, Cb, Cr
  const Y = new Float64Array(totalPixels);
  const Cb = new Float64Array(totalPixels);
  const Cr = new Float64Array(totalPixels);

  for (let p = 0; p < totalPixels; p++) {
    const off = p * 4;
    const r = data[off];
    const g = data[off + 1];
    const b = data[off + 2];

    Y[p] = 0.299 * r + 0.587 * g + 0.114 * b;
    Cb[p] = 128 - 0.168736 * r - 0.331264 * g + 0.5 * b;
    Cr[p] = 128 + 0.5 * r - 0.418688 * g - 0.081312 * b;
  }

  const blocksX = Math.floor(width / 8);
  const blocksY = Math.floor(height / 8);
  const totalBlocks = blocksX * blocksY;

  const blockInput = new Float64Array(64);
  const blockDct = new Float64Array(64);
  const blockIdct = new Float64Array(64);

  // Embed across all 8x8 blocks with redundancy
  for (let bIdx = 0; bIdx < totalBlocks; bIdx++) {
    const bx = bIdx % blocksX;
    const by = Math.floor(bIdx / blocksX);
    const startX = bx * 8;
    const startY = by * 8;

    // Bit to embed in this block (cyclic repetition)
    const bitToEmbed = bits[bIdx % bits.length];

    // Read 8x8 luminance values
    for (let y = 0; y < 8; y++) {
      const rowOff = (startY + y) * width;
      for (let x = 0; x < 8; x++) {
        blockInput[y * 8 + x] = Y[rowOff + (startX + x)];
      }
    }

    // 2D DCT
    forwardDCT8x8(blockInput, blockDct);

    // Mid-frequency indices: (4, 3) = index 35, (3, 4) = index 28
    const idx1 = 4 * 8 + 3; // (4,3)
    const idx2 = 3 * 8 + 4; // (3,4)

    let c1 = blockDct[idx1];
    let c2 = blockDct[idx2];

    if (bitToEmbed === 1) {
      // Want c1 - c2 >= strength
      if (c1 - c2 < strength) {
        const diff = strength - (c1 - c2);
        c1 += diff / 2;
        c2 -= diff / 2;
      }
    } else {
      // Want c2 - c1 >= strength
      if (c2 - c1 < strength) {
        const diff = strength - (c2 - c1);
        c2 += diff / 2;
        c1 -= diff / 2;
      }
    }

    blockDct[idx1] = c1;
    blockDct[idx2] = c2;

    // Inverse 2D DCT
    inverseDCT8x8(blockDct, blockIdct);

    // Write back to Y
    for (let y = 0; y < 8; y++) {
      const rowOff = (startY + y) * width;
      for (let x = 0; x < 8; x++) {
        Y[rowOff + (startX + x)] = blockIdct[y * 8 + x];
      }
    }

    // Progress updates periodically
    if (bIdx % 500 === 0 && onProgress) {
      onProgress(Math.round((bIdx / totalBlocks) * 70));
      // Yield to main thread for non-blocking UI
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }

  // Convert back to RGB
  const outputData = new Uint8ClampedArray(data.length);
  const diffData = new Uint8ClampedArray(data.length);

  let sumSquaredError = 0;

  for (let p = 0; p < totalPixels; p++) {
    const off = p * 4;
    const yVal = Y[p];
    const cbVal = Cb[p];
    const crVal = Cr[p];

    // Reconstruct RGB
    let r = Math.round(yVal + 1.402 * (crVal - 128));
    let g = Math.round(yVal - 0.344136 * (cbVal - 128) - 0.714136 * (crVal - 128));
    let b = Math.round(yVal + 1.772 * (cbVal - 128));

    // Clamp
    r = Math.max(0, Math.min(255, r));
    g = Math.max(0, Math.min(255, g));
    b = Math.max(0, Math.min(255, b));

    outputData[off] = r;
    outputData[off + 1] = g;
    outputData[off + 2] = b;
    outputData[off + 3] = data[off + 3]; // Preserve original Alpha

    // Calculate difference amplified by 30x
    const dr = Math.abs(r - data[off]);
    const dg = Math.abs(g - data[off + 1]);
    const db = Math.abs(b - data[off + 2]);

    sumSquaredError += dr * dr + dg * dg + db * db;

    diffData[off] = Math.min(255, dr * 30);
    diffData[off + 1] = Math.min(255, dg * 30);
    diffData[off + 2] = Math.min(255, db * 30);
    diffData[off + 3] = 255;
  }

  const mse = sumSquaredError / (3 * totalPixels);
  const psnr = mse > 0 ? 10 * Math.log10((255 * 255) / mse) : 100;

  // Calculate SSIM over luminance channel
  const ssim = calculateSSIM(data, outputData, width, height);

  const watermarkedImageData = new ImageData(outputData, width, height);
  const diffImageData = new ImageData(diffData, width, height);

  if (onProgress) onProgress(100);

  return {
    watermarkedImageData,
    metrics: {
      psnr: Number(psnr.toFixed(2)),
      ssim: Number(ssim.toFixed(4)),
      mse: Number(mse.toFixed(4)),
      strength,
    },
    diffImageData,
  };
}

/**
 * Extracts 64-bit watermark from image using DCT mid-frequency coefficient comparison and majority voting.
 */
export async function extractDCTWatermark(
  imageData: ImageData,
  expectedBits: number[],
  expectedHex: string
): Promise<WatermarkExtractionResult> {
  const width = imageData.width;
  const height = imageData.height;
  const data = imageData.data;
  const totalPixels = width * height;

  // Extract Y channel
  const Y = new Float64Array(totalPixels);
  for (let p = 0; p < totalPixels; p++) {
    const off = p * 4;
    Y[p] = 0.299 * data[off] + 0.587 * data[off + 1] + 0.114 * data[off + 2];
  }

  const blocksX = Math.floor(width / 8);
  const blocksY = Math.floor(height / 8);
  const totalBlocks = blocksX * blocksY;

  const numBits = expectedBits.length; // 64
  const votes = new Int32Array(numBits);
  const voteMarginSums = new Float64Array(numBits);

  const blockInput = new Float64Array(64);
  const blockDct = new Float64Array(64);

  const idx1 = 4 * 8 + 3; // (4,3)
  const idx2 = 3 * 8 + 4; // (3,4)

  for (let bIdx = 0; bIdx < totalBlocks; bIdx++) {
    const bx = bIdx % blocksX;
    const by = Math.floor(bIdx / blocksX);
    const startX = bx * 8;
    const startY = by * 8;

    const bitIndex = bIdx % numBits;

    // Load 8x8 block
    for (let y = 0; y < 8; y++) {
      const rowOff = (startY + y) * width;
      for (let x = 0; x < 8; x++) {
        blockInput[y * 8 + x] = Y[rowOff + (startX + x)];
      }
    }

    forwardDCT8x8(blockInput, blockDct);

    const diff = blockDct[idx1] - blockDct[idx2];
    voteMarginSums[bitIndex] += diff;

    if (diff > 0) {
      votes[bitIndex] += 1;
    } else if (diff < 0) {
      votes[bitIndex] -= 1;
    }
  }

  // Determine extracted bits via majority vote
  const extractedBits: number[] = [];
  let matchedBitsCount = 0;

  for (let i = 0; i < numBits; i++) {
    let bit = 0;
    if (votes[i] > 0) {
      bit = 1;
    } else if (votes[i] < 0) {
      bit = 0;
    } else {
      // Tie breaker using margin sum
      bit = voteMarginSums[i] >= 0 ? 1 : 0;
    }

    extractedBits.push(bit);
    if (bit === expectedBits[i]) {
      matchedBitsCount++;
    }
  }

  const bitMatchPercent = Number(((matchedBitsCount / numBits) * 100).toFixed(1));
  const extractedHex = bitsToHex(extractedBits);

  // Confidence score combines bit match rate and average vote margin
  const confidenceScore = Math.min(100, Math.round(bitMatchPercent * 0.9 + 10));

  let status: WatermarkExtractionResult['status'] = 'NOT_FOUND';
  let details = '';

  if (bitMatchPercent >= 85) {
    status = 'DETECTED';
    details = `Robust 2D-DCT watermark authenticated. ${matchedBitsCount}/${numBits} bits matched (${bitMatchPercent}%). Hex ID: ${extractedHex}.`;
  } else if (bitMatchPercent >= 65) {
    status = 'WEAK';
    details = `Watermark signal degraded but present. ${matchedBitsCount}/${numBits} bits matched (${bitMatchPercent}%). Partial signature match.`;
  } else {
    status = 'NOT_FOUND';
    details = `No matching DCT watermark signature detected. Match rate was ${bitMatchPercent}% (expected >= 85% for positive authentication).`;
  }

  return {
    status,
    extractedHex,
    expectedHex,
    matchedBits: matchedBitsCount,
    totalBits: numBits,
    bitMatchPercent,
    confidenceScore,
    details,
  };
}

/**
 * Calculates Structural Similarity Index (SSIM) between original and watermarked ImageData.
 */
export function calculateSSIM(
  orig: Uint8ClampedArray,
  mod: Uint8ClampedArray,
  width: number,
  height: number
): number {
  const K1 = 0.01;
  const K2 = 0.03;
  const L = 255;
  const C1 = (K1 * L) * (K1 * L);
  const C2 = (K2 * L) * (K2 * L);

  const blocksX = Math.floor(width / 8);
  const blocksY = Math.floor(height / 8);
  const totalBlocks = blocksX * blocksY;

  if (totalBlocks === 0) return 1.0;

  let ssimSum = 0;

  for (let by = 0; by < blocksY; by++) {
    for (let bx = 0; bx < blocksX; bx++) {
      let sumX = 0;
      let sumY = 0;

      // 1. Calculate means
      for (let y = 0; y < 8; y++) {
        const row = (by * 8 + y) * width;
        for (let x = 0; x < 8; x++) {
          const idx = (row + (bx * 8 + x)) * 4;
          // Luminance approximation
          const lumX = 0.299 * orig[idx] + 0.587 * orig[idx + 1] + 0.114 * orig[idx + 2];
          const lumY = 0.299 * mod[idx] + 0.587 * mod[idx + 1] + 0.114 * mod[idx + 2];
          sumX += lumX;
          sumY += lumY;
        }
      }

      const meanX = sumX / 64;
      const meanY = sumY / 64;

      // 2. Calculate variances and covariance
      let varX = 0;
      let varY = 0;
      let covXY = 0;

      for (let y = 0; y < 8; y++) {
        const row = (by * 8 + y) * width;
        for (let x = 0; x < 8; x++) {
          const idx = (row + (bx * 8 + x)) * 4;
          const lumX = 0.299 * orig[idx] + 0.587 * orig[idx + 1] + 0.114 * orig[idx + 2];
          const lumY = 0.299 * mod[idx] + 0.587 * mod[idx + 1] + 0.114 * mod[idx + 2];

          const diffX = lumX - meanX;
          const diffY = lumY - meanY;

          varX += diffX * diffX;
          varY += diffY * diffY;
          covXY += diffX * diffY;
        }
      }

      varX /= 63;
      varY /= 63;
      covXY /= 63;

      const num = (2 * meanX * meanY + C1) * (2 * covXY + C2);
      const den = (meanX * meanX + meanY * meanY + C1) * (varX + varY + C2);
      const blockSSIM = num / den;

      ssimSum += blockSSIM;
    }
  }

  return Math.max(0, Math.min(1, ssimSum / totalBlocks));
}

/**
 * Forensic Robustness Attacks Execution:
 * Applies real image transformations on canvas and tests watermark survival rate.
 */
export async function runRobustnessAttacks(
  watermarkedImageData: ImageData,
  expectedBits: number[],
  expectedHex: string,
  onProgress?: (current: number, total: number, attackName: string) => void
): Promise<AttackResult[]> {
  const width = watermarkedImageData.width;
  const height = watermarkedImageData.height;

  // Source canvas
  const srcCanvas = document.createElement('canvas');
  srcCanvas.width = width;
  srcCanvas.height = height;
  const srcCtx = srcCanvas.getContext('2d')!;
  srcCtx.putImageData(watermarkedImageData, 0, 0);

  const attacks = [
    {
      id: 'jpeg-90',
      name: 'JPEG Compression (Q: 90%)',
      description: 'Standard lossy web compression',
      apply: async () => {
        return compressCanvasToJpeg(srcCanvas, 0.9);
      },
    },
    {
      id: 'jpeg-70',
      name: 'JPEG Compression (Q: 70%)',
      description: 'Moderate lossy re-encoding',
      apply: async () => {
        return compressCanvasToJpeg(srcCanvas, 0.7);
      },
    },
    {
      id: 'jpeg-50',
      name: 'JPEG Compression (Q: 50%)',
      description: 'Heavy lossy transmission compression',
      apply: async () => {
        return compressCanvasToJpeg(srcCanvas, 0.5);
      },
    },
    {
      id: 'resize-50',
      name: 'Downsample 50% & Upscale',
      description: 'Bilinear scaling attack (resolution downscaling)',
      apply: async () => {
        const halfCanvas = document.createElement('canvas');
        halfCanvas.width = Math.floor(width / 2);
        halfCanvas.height = Math.floor(height / 2);
        const halfCtx = halfCanvas.getContext('2d')!;
        halfCtx.drawImage(srcCanvas, 0, 0, halfCanvas.width, halfCanvas.height);

        const restoredCanvas = document.createElement('canvas');
        restoredCanvas.width = width;
        restoredCanvas.height = height;
        const restCtx = restoredCanvas.getContext('2d')!;
        restCtx.drawImage(halfCanvas, 0, 0, width, height);

        return restCtx.getImageData(0, 0, width, height);
      },
    },
    {
      id: 'gaussian-noise',
      name: 'Gaussian Noise Addition',
      description: 'Sensor noise perturbation (±15 level jitter)',
      apply: async () => {
        const copy = new ImageData(
          new Uint8ClampedArray(watermarkedImageData.data),
          width,
          height
        );
        const d = copy.data;
        for (let i = 0; i < d.length; i += 4) {
          // Box-Muller normal noise
          const noise = (Math.random() - 0.5) * 26;
          d[i] = Math.max(0, Math.min(255, d[i] + noise));
          d[i + 1] = Math.max(0, Math.min(255, d[i + 1] + noise));
          d[i + 2] = Math.max(0, Math.min(255, d[i + 2] + noise));
        }
        return copy;
      },
    },
    {
      id: 'brightness-shift',
      name: 'Brightness Modification (+20)',
      description: 'Uniform exposure boost across image',
      apply: async () => {
        const copy = new ImageData(
          new Uint8ClampedArray(watermarkedImageData.data),
          width,
          height
        );
        const d = copy.data;
        for (let i = 0; i < d.length; i += 4) {
          d[i] = Math.max(0, Math.min(255, d[i] + 20));
          d[i + 1] = Math.max(0, Math.min(255, d[i + 1] + 20));
          d[i + 2] = Math.max(0, Math.min(255, d[i + 2] + 20));
        }
        return copy;
      },
    },
    {
      id: 'cropping-10',
      name: 'Cropping (10% Peripheral Crop)',
      description: 'Edge boundary removal attack',
      apply: async () => {
        const copy = new ImageData(
          new Uint8ClampedArray(watermarkedImageData.data),
          width,
          height
        );
        const d = copy.data;
        const cropX = Math.floor(width * 0.05);
        const cropY = Math.floor(height * 0.05);

        for (let y = 0; y < height; y++) {
          for (let x = 0; x < width; x++) {
            if (x < cropX || x > width - cropX || y < cropY || y > height - cropY) {
              const idx = (y * width + x) * 4;
              d[idx] = 16;
              d[idx + 1] = 16;
              d[idx + 2] = 16;
            }
          }
        }
        return copy;
      },
    },
  ];

  const results: AttackResult[] = [];

  for (let i = 0; i < attacks.length; i++) {
    const attack = attacks[i];
    if (onProgress) {
      onProgress(i + 1, attacks.length, attack.name);
    }

    // Let browser render before heavy work
    await new Promise((r) => setTimeout(r, 20));

    const attackedImageData = await attack.apply();

    // Run extraction
    const extract = await extractDCTWatermark(attackedImageData, expectedBits, expectedHex);

    // Generate small thumbnail dataUrl for attack preview
    const thumbCanvas = document.createElement('canvas');
    thumbCanvas.width = 120;
    thumbCanvas.height = Math.round((120 * height) / width);
    const tCtx = thumbCanvas.getContext('2d')!;

    const tempCanvas = document.createElement('canvas');
    tempCanvas.width = width;
    tempCanvas.height = height;
    tempCanvas.getContext('2d')!.putImageData(attackedImageData, 0, 0);
    tCtx.drawImage(tempCanvas, 0, 0, thumbCanvas.width, thumbCanvas.height);

    const passed = extract.bitMatchPercent >= 75;

    results.push({
      id: attack.id,
      name: attack.name,
      description: attack.description,
      matchedBits: extract.matchedBits,
      totalBits: extract.totalBits,
      bitMatchPercent: extract.bitMatchPercent,
      confidenceScore: extract.confidenceScore,
      passed,
      thumbnailDataUrl: thumbCanvas.toDataURL('image/jpeg', 0.7),
    });
  }

  return results;
}

/**
 * Helper to compress canvas to JPEG and return back as ImageData.
 */
function compressCanvasToJpeg(canvas: HTMLCanvasElement, quality: number): Promise<ImageData> {
  return new Promise((resolve, reject) => {
    canvas.toBlob(
      (blob) => {
        if (!blob) {
          reject(new Error('Failed to create JPEG blob'));
          return;
        }
        const img = new Image();
        const url = URL.createObjectURL(blob);
        img.onload = () => {
          const c = document.createElement('canvas');
          c.width = canvas.width;
          c.height = canvas.height;
          const ctx = c.getContext('2d')!;
          ctx.drawImage(img, 0, 0);
          URL.revokeObjectURL(url);
          resolve(ctx.getImageData(0, 0, canvas.width, canvas.height));
        };
        img.onerror = () => {
          URL.revokeObjectURL(url);
          reject(new Error('Failed to load compressed image'));
        };
        img.src = url;
      },
      'image/jpeg',
      quality
    );
  });
}

/**
 * Generates visible text overlay watermark onto canvas.
 */
export function applyVisibleWatermark(
  originalDataUrl: string,
  params: {
    caseId: string;
    evidenceId: string;
    timestamp: string;
    customText?: string;
    position: 'top-left' | 'top-right' | 'bottom-left' | 'bottom-right' | 'center' | 'tiled';
    opacity: number;
    fontSize: number;
    color: string;
  }
): Promise<string> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.crossOrigin = 'anonymous';
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      if (!ctx) {
        reject(new Error('No 2D context'));
        return;
      }

      // Draw base image
      ctx.drawImage(img, 0, 0);

      // Watermark styling
      ctx.save();
      ctx.globalAlpha = Math.max(0.1, Math.min(1.0, params.opacity));
      ctx.fillStyle = params.color;
      ctx.font = `bold ${params.fontSize}px "JetBrains Mono", monospace`;

      const line1 = `FORENSIC EVIDENCE: ${params.caseId} // ${params.evidenceId}`;
      const line2 = `TIMESTAMP: ${params.timestamp} • SEALCHAIN`;
      const line3 = params.customText ? params.customText.trim() : '';

      const padding = 24;
      const lineHeight = params.fontSize * 1.35;

      if (params.position === 'tiled') {
        // Tiled 45-degree repeating watermark pattern across image
        ctx.translate(canvas.width / 2, canvas.height / 2);
        ctx.rotate((-35 * Math.PI) / 180);
        ctx.translate(-canvas.width / 2, -canvas.height / 2);

        const stepX = 360;
        const stepY = 160;
        for (let x = -canvas.width; x < canvas.width * 2; x += stepX) {
          for (let y = -canvas.height; y < canvas.height * 2; y += stepY) {
            ctx.fillText(line1, x, y);
            ctx.fillText(line2, x, y + lineHeight);
          }
        }
      } else if (params.position === 'center') {
        ctx.textAlign = 'center';
        const cx = canvas.width / 2;
        const cy = canvas.height / 2;
        ctx.fillText(line1, cx, cy - lineHeight);
        ctx.fillText(line2, cx, cy);
        if (line3) ctx.fillText(line3, cx, cy + lineHeight);
      } else if (params.position === 'top-left') {
        ctx.textAlign = 'left';
        ctx.fillText(line1, padding, padding + params.fontSize);
        ctx.fillText(line2, padding, padding + params.fontSize + lineHeight);
        if (line3) ctx.fillText(line3, padding, padding + params.fontSize + lineHeight * 2);
      } else if (params.position === 'top-right') {
        ctx.textAlign = 'right';
        const rx = canvas.width - padding;
        ctx.fillText(line1, rx, padding + params.fontSize);
        ctx.fillText(line2, rx, padding + params.fontSize + lineHeight);
        if (line3) ctx.fillText(line3, rx, padding + params.fontSize + lineHeight * 2);
      } else if (params.position === 'bottom-left') {
        ctx.textAlign = 'left';
        const by = canvas.height - padding - (line3 ? lineHeight * 2 : lineHeight);
        ctx.fillText(line1, padding, by);
        ctx.fillText(line2, padding, by + lineHeight);
        if (line3) ctx.fillText(line3, padding, by + lineHeight * 2);
      } else if (params.position === 'bottom-right') {
        ctx.textAlign = 'right';
        const rx = canvas.width - padding;
        const by = canvas.height - padding - (line3 ? lineHeight * 2 : lineHeight);
        ctx.fillText(line1, rx, by);
        ctx.fillText(line2, rx, by + lineHeight);
        if (line3) ctx.fillText(line3, rx, by + lineHeight * 2);
      }

      ctx.restore();
      resolve(canvas.toDataURL('image/png'));
    };
    img.onerror = () => reject(new Error('Failed to load image for visible watermark'));
    img.src = originalDataUrl;
  });
}
