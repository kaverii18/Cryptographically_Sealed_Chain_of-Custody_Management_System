/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Generates an authentic digital forensic evidence image on an HTML5 canvas
 * and returns it as a PNG Data URL along with its binary ArrayBuffer for exact SHA-256 hashing.
 */
export function generateSampleForensicImage(): {
  dataUrl: string;
  blob: Blob;
  fileName: string;
  fileSize: number;
  mimeType: string;
} {
  const width = 800;
  const height = 500;
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');

  if (!ctx) {
    throw new Error('Canvas 2D context unavailable');
  }

  // Forensic background - dark navy grid with metallic slate textures
  ctx.fillStyle = '#0a0f1d';
  ctx.fillRect(0, 0, width, height);

  // Grid background
  ctx.strokeStyle = 'rgba(30, 58, 95, 0.4)';
  ctx.lineWidth = 1;
  for (let x = 0; x < width; x += 40) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, height);
    ctx.stroke();
  }
  for (let y = 0; y < height; y += 40) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }

  // Evidence Bag Border / Tamper-evident Seal outline
  ctx.strokeStyle = '#0284c7';
  ctx.lineWidth = 3;
  ctx.strokeRect(24, 24, width - 48, height - 48);

  // Evidence Seal Header
  ctx.fillStyle = '#0369a1';
  ctx.fillRect(24, 24, width - 48, 54);

  ctx.fillStyle = '#ffffff';
  ctx.font = 'bold 20px "Plus Jakarta Sans", sans-serif';
  ctx.fillText('DIGITAL FORENSICS DIVISION • CHAIN OF CUSTODY EVIDENCE', 44, 58);

  // Tamper warning banner
  ctx.fillStyle = '#b45309';
  ctx.fillRect(24, 78, width - 48, 26);
  ctx.fillStyle = '#fef3c7';
  ctx.font = 'bold 12px "JetBrains Mono", monospace';
  ctx.fillText('WARNING: SEALED EVIDENCE — DO NOT BREAK INTEGRITY SEAL WITHOUT COURT ORDER', 44, 96);

  // Draw Seized Hardware Graphic (NVMe SSD M.2 drive with gold connectors)
  const chipX = 70;
  const chipY = 140;
  const chipW = 280;
  const chipH = 90;

  // PCB Board (Dark Green)
  ctx.fillStyle = '#064e3b';
  ctx.fillRect(chipX, chipY, chipW, chipH);
  ctx.strokeStyle = '#047857';
  ctx.lineWidth = 2;
  ctx.strokeRect(chipX, chipY, chipW, chipH);

  // Controller Chip (Metallic Slate)
  ctx.fillStyle = '#1e293b';
  ctx.fillRect(chipX + 30, chipY + 18, 60, 54);
  ctx.fillStyle = '#94a3b8';
  ctx.font = '9px "JetBrains Mono", monospace';
  ctx.fillText('PHISON', chipX + 40, chipY + 44);
  ctx.fillText('PS5018', chipX + 40, chipY + 56);

  // NAND Flash Memory Modules
  ctx.fillStyle = '#0f172a';
  ctx.fillRect(chipX + 110, chipY + 15, 70, 60);
  ctx.fillRect(chipX + 190, chipY + 15, 70, 60);
  ctx.fillStyle = '#64748b';
  ctx.fillText('TOSHIBA', chipX + 120, chipY + 44);
  ctx.fillText('1TB NAND', chipX + 120, chipY + 56);
  ctx.fillText('TOSHIBA', chipX + 200, chipY + 44);
  ctx.fillText('1TB NAND', chipX + 200, chipY + 56);

  // Gold PCIe Contacts
  ctx.fillStyle = '#eab308';
  for (let i = 0; i < 28; i++) {
    ctx.fillRect(chipX + chipW - 4, chipY + 12 + i * 2.5, 4, 1.8);
  }

  // Evidence Metadata Card Panel inside image
  ctx.fillStyle = 'rgba(15, 23, 42, 0.9)';
  ctx.fillRect(390, 130, 360, 220);
  ctx.strokeStyle = '#334155';
  ctx.lineWidth = 1;
  ctx.strokeRect(390, 130, 360, 220);

  ctx.fillStyle = '#38bdf8';
  ctx.font = 'bold 13px "JetBrains Mono", monospace';
  ctx.fillText('EVIDENCE SPECIFICATION', 410, 160);

  ctx.fillStyle = '#94a3b8';
  ctx.font = '12px "Plus Jakarta Sans", sans-serif';
  ctx.fillText('Case Reference:', 410, 190);
  ctx.fillText('Evidence Tag:', 410, 215);
  ctx.fillText('Recovered Item:', 410, 240);
  ctx.fillText('Seizure Date:', 410, 265);
  ctx.fillText('Primary Agent:', 410, 290);
  ctx.fillText('Physical Condition:', 410, 315);

  ctx.fillStyle = '#f8fafc';
  ctx.font = 'bold 12px "JetBrains Mono", monospace';
  ctx.fillText('CAS-2026-9812 (Op DeepVault)', 520, 190);
  ctx.fillText('EVD-001-A', 520, 215);
  ctx.fillText('Samsung 990 Pro 2TB M.2 SSD', 520, 240);
  ctx.fillText('2026-10-18 06:14:00 UTC', 520, 265);
  ctx.fillText('Det. Elena Rostova #CF-409', 520, 290);
  ctx.fillStyle = '#34d399';
  ctx.fillText('INTACT / WRITE-BLOCKED', 520, 315);

  // Barcode visualization at bottom
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(70, 380, 280, 50);
  ctx.fillStyle = '#000000';
  const barPattern = [3, 1, 2, 4, 1, 3, 2, 1, 4, 2, 1, 3, 4, 2, 1, 2, 3, 1, 4, 2, 3, 1, 2, 4, 1, 3, 2, 4, 1, 3, 2, 1, 3, 2, 4];
  let bx = 85;
  for (let i = 0; i < barPattern.length; i++) {
    const w = barPattern[i];
    if (i % 2 === 0) {
      ctx.fillRect(bx, 388, w, 34);
    }
    bx += w + 2;
  }
  ctx.fillStyle = '#000000';
  ctx.font = '10px "JetBrains Mono", monospace';
  ctx.fillText('* EVD-001-A-CAS-2026-9812 *', 115, 426);

  // Digital Security Stamp
  ctx.strokeStyle = '#38bdf8';
  ctx.lineWidth = 1.5;
  ctx.strokeRect(390, 370, 360, 60);
  ctx.fillStyle = '#e2e8f0';
  ctx.font = '11px "JetBrains Mono", monospace';
  ctx.fillText('CRYPTO INTEGRITY SEAL: P-256 ECDSA ACTIVE', 410, 395);
  ctx.fillStyle = '#94a3b8';
  ctx.font = '10px "JetBrains Mono", monospace';
  ctx.fillText('SECURE HASH ALGORITHM: NIST FIPS 180-4 SHA-256', 410, 415);

  const dataUrl = canvas.toDataURL('image/png');

  // Convert to binary blob
  const byteString = atob(dataUrl.split(',')[1]);
  const mimeString = dataUrl.split(',')[0].split(':')[1].split(';')[0];
  const ab = new ArrayBuffer(byteString.length);
  const ia = new Uint8Array(ab);
  for (let i = 0; i < byteString.length; i++) {
    ia[i] = byteString.charCodeAt(i);
  }
  const blob = new Blob([ab], { type: mimeString });

  return {
    dataUrl,
    blob,
    fileName: 'seized_m2_ssd_evd001a.png',
    fileSize: blob.size,
    mimeType: 'image/png',
  };
}
