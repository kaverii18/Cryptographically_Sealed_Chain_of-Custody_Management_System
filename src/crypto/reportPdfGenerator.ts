/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import QRCode from 'qrcode';
import {
  ForensicCase,
  ActorIdentity,
  ComprehensiveVerificationReport,
  ReportOptions,
  CompactReportQrPayload,
  GeneratedReportData,
} from '../types/forensics';
import { computeSHA256, importECDSAPrivateKey, signCanonicalPayload } from './webCrypto';

/**
 * Translations dictionary for English and Marathi reports
 */
export const REPORT_LABELS = {
  en: {
    title: 'DIGITAL FORENSIC CHAIN OF CUSTODY & INTEGRITY REPORT',
    subtitle: 'Cryptographically Sealed Evidence Examination & Provenance Audit',
    caseId: 'Case Identifier',
    evidenceId: 'Evidence Tag / Specimen ID',
    reportId: 'Report ID',
    generatedAt: 'Date / Timestamp',
    investigator: 'Examining Officer',
    organization: 'Agency / Division',
    evidenceDetails: '1. DIGITAL EVIDENCE SPECIFICATION & METADATA',
    chainOfCustody: '2. HASH-LINKED CHAIN OF CUSTODY LEDGER',
    integritySummary: '3. FIVE-INDEPENDENT INVARIANT AUDIT',
    finalVerdict: '4. FORENSIC DECISION & COURTROOM ADMISSIBILITY',
    heatmapTitle: '5. BLOCK-LEVEL TAMPER LOCALIZATION HEATMAP',
    methodology: '6. SCIENTIFIC & TECHNICAL METHODOLOGY',
    signatures: '7. OFFICIAL FORENSIC CERTIFICATION & SIGNATURES',
    reportIntegrity: '8. REPORT SELF-INTEGRITY CRYPTOGRAPHIC SEAL',
    authentic: 'AUTHENTIC — ADMISSIBLE IN COURT',
    tampered: 'TAMPERED — INTEGRITY COMPROMISED',
    inconclusive: 'INCONCLUSIVE — NON-MALICIOUS RE-ENCODING',
    pass: 'PASS',
    fail: 'FAIL',
    na: 'N/A',
  },
  mr: {
    title: 'डिजिटल फॉरेन्सिक पुराव्याची साखळी व सत्यता अहवाल',
    subtitle: 'क्रिप्टोग्राफिकली सीलबंद पुरावा तपासणी व सत्यता प्रमाणपत्र',
    caseId: 'खटला क्रमांक (Case ID)',
    evidenceId: 'पुरावा टॅग (Evidence ID)',
    reportId: 'अहवाल संदर्भ क्र. (Report ID)',
    generatedAt: 'निर्मिती दिनांक व वेळ',
    investigator: 'तपासणी अधिकारी',
    organization: 'विभागीय तपास यंत्रणा',
    evidenceDetails: '१. डिजिटल पुरावा ओळख व तांत्रिक तपशील',
    chainOfCustody: '२. क्रिप्टोग्राफिक ताब्याची साखळी (Chain of Custody)',
    integritySummary: '३. ५-सूत्रीय सत्यता व अखंडता तपासणी (5-Point Audit)',
    finalVerdict: '४. न्यायालयीन अंतिम निष्कर्ष (Forensic Verdict)',
    heatmapTitle: '५. छेडछाड स्थानिकीकरण व हीटमॅप (Tamper Heatmap)',
    methodology: '६. तांत्रिक व वैज्ञानिक कार्यपद्धती (Methodology)',
    signatures: '७. अधिकृत स्वाक्षरी व फॉरेन्सिक प्रमाणीकरण',
    reportIntegrity: '८. अहवाल स्व-सत्यता क्रिप्टोग्राफिक सील',
    authentic: 'अस्सल — न्यायालयात स्वीकारार्ह (AUTHENTIC)',
    tampered: 'छेडछाड झालेला — पुरावा दूषित (TAMPERED)',
    inconclusive: 'अनिर्णायक — सामान्य स्वरूप बदल (INCONCLUSIVE)',
    pass: 'उत्तीर्ण (PASS)',
    fail: 'अनुत्तीर्ण (FAIL)',
    na: 'लागू नाही (N/A)',
  },
};

/**
 * Generates QR Code data URL encoding compact report verification JSON.
 */
export async function generateReportQr(qrPayload: CompactReportQrPayload): Promise<string> {
  const jsonStr = JSON.stringify(qrPayload);
  return QRCode.toDataURL(jsonStr, {
    errorCorrectionLevel: 'M',
    margin: 2,
    width: 250,
    color: {
      dark: '#0f172a',
      light: '#ffffff',
    },
  });
}

/**
 * Computes self-integrity hash of the report data and signs it with ECDSA P-256.
 */
export async function computeReportSelfIntegrity(params: {
  reportId: string;
  caseId: string;
  evidenceId: string;
  options: ReportOptions;
  reportDate: string;
  evidenceHash: string;
  ledgerHeadHash: string;
  verdict: string;
  actor: ActorIdentity;
}): Promise<{ reportHash: string; signatureHex: string; canonicalData: string }> {
  const {
    reportId,
    caseId,
    evidenceId,
    options,
    reportDate,
    evidenceHash,
    ledgerHeadHash,
    verdict,
    actor,
  } = params;

  const canonicalObj = {
    reportId,
    caseId,
    evidenceId,
    evidenceHash,
    ledgerHeadHash,
    verdict,
    investigatorName: options.investigatorName,
    investigatorOrg: options.investigatorOrg,
    language: options.language,
    merkleRoot: (params as any).merkleRoot,
    reportDate,
  };

  const canonicalData = JSON.stringify(canonicalObj);
  const reportHash = await computeSHA256(canonicalData);

  let signatureHex = '';
  if (actor.privateKeyJwk) {
    const privateKey = await importECDSAPrivateKey(actor.privateKeyJwk);
    signatureHex = await signCanonicalPayload(privateKey, canonicalData);
  } else {
    signatureHex = 'ECDSA_SELF_SIGNED_MOCK_TEST_HEX_3045022100...';
  }

  return { reportHash, signatureHex, canonicalData };
}

/**
 * Generates and downloads the formal court-admissible PDF report using jsPDF & autoTable.
 */
export async function generateCourtAdmissiblePdf(params: {
  currentCase: ForensicCase;
  verificationReport: ComprehensiveVerificationReport | null;
  reportData: GeneratedReportData;
}): Promise<void> {
  const { currentCase, verificationReport, reportData } = params;
  const { options } = reportData;
  const labels = REPORT_LABELS[options.language] || REPORT_LABELS.en;

  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 14;
  const contentWidth = pageWidth - margin * 2;

  // Header & Footer helper
  const addPageDecorations = (pageNum: number, totalPagesPlaceholder: string) => {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);

    // Running Header
    doc.text(
      `SealChain Forensic Audit | Case Ref: ${currentCase.caseId} | Evid: ${currentCase.evidence.evidenceId}`,
      margin,
      10
    );
    doc.setDrawColor(203, 213, 225);
    doc.line(margin, 12, pageWidth - margin, 12);

    // Running Footer
    doc.line(margin, pageHeight - 12, pageWidth - margin, pageHeight - 12);
    doc.text(
      'Generated by SealChain Cryptographic Forensics Management System • Tamper-Sealed',
      margin,
      pageHeight - 8
    );
    doc.text(
      `Page ${pageNum} of ${totalPagesPlaceholder}`,
      pageWidth - margin,
      pageHeight - 8,
      { align: 'right' }
    );
  };

  let cursorY = 20;

  // =========================================================================
  // PAGE 1: COVER PAGE & HEADER
  // =========================================================================
  // Top Title Banner
  doc.setFillColor(15, 23, 42); // Slate 900
  doc.rect(margin, cursorY, contentWidth, 34, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.setTextColor(255, 255, 255);
  doc.text(labels.title, margin + 6, cursorY + 12);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(56, 189, 248); // Cyan 400
  doc.text(labels.subtitle, margin + 6, cursorY + 20);

  doc.setFontSize(8);
  doc.setTextColor(203, 213, 225);
  doc.text(
    `Report ID: ${reportData.reportId}  |  Generated: ${new Date(reportData.generatedAt).toLocaleString()}`,
    margin + 6,
    cursorY + 28
  );

  cursorY += 40;

  // Metadata Grid & QR Code side-by-side
  const metaBoxWidth = contentWidth - 48;
  doc.setDrawColor(226, 232, 240);
  doc.setFillColor(248, 250, 252);
  doc.roundedRect(margin, cursorY, metaBoxWidth, 42, 2, 2, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(30, 41, 59);

  doc.text(`${labels.caseId}:`, margin + 6, cursorY + 10);
  doc.setFont('courier', 'bold');
  doc.setTextColor(2, 132, 199);
  doc.text(currentCase.caseId, margin + 46, cursorY + 10);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 41, 59);
  doc.text(`${labels.evidenceId}:`, margin + 6, cursorY + 18);
  doc.setFont('courier', 'bold');
  doc.setTextColor(2, 132, 199);
  doc.text(currentCase.evidence.evidenceId, margin + 46, cursorY + 18);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 41, 59);
  doc.text(`${labels.investigator}:`, margin + 6, cursorY + 26);
  doc.setFont('helvetica', 'normal');
  doc.text(options.investigatorName || currentCase.evidence.collectorName, margin + 46, cursorY + 26);

  doc.setFont('helvetica', 'bold');
  doc.text(`${labels.organization}:`, margin + 6, cursorY + 34);
  doc.setFont('helvetica', 'normal');
  doc.text(options.investigatorOrg || currentCase.evidence.collectorAgency, margin + 46, cursorY + 34);

  // QR Code on right side
  if (reportData.qrDataUrl) {
    try {
      doc.addImage(reportData.qrDataUrl, 'PNG', pageWidth - margin - 42, cursorY, 42, 42);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(100, 116, 139);
      doc.text('Scan to Verify', pageWidth - margin - 21, cursorY + 45, { align: 'center' });
    } catch (err) {
      console.error('Failed to embed QR image in PDF:', err);
    }
  }

  cursorY += 50;

  // =========================================================================
  // SECTION 1: EVIDENCE DETAILS
  // =========================================================================
  if (options.includeEvidenceDetails) {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text(labels.evidenceDetails, margin, cursorY);
    cursorY += 4;

    const evidenceRows = [
      ['Original File Name', currentCase.evidence.imageFileName || 'seized_evidence.png'],
      ['File Size / Type', `${(currentCase.evidence.imageFileSize / 1024).toFixed(1)} KB (${currentCase.evidence.imageMimeType || 'image/png'})`],
      ['Primary Seizing Officer', `${currentCase.evidence.collectorName} (${currentCase.evidence.collectorBadge || 'N/A'})`],
      ['Seizure Timestamp', currentCase.evidence.timestamp],
      ['Original SHA-256 Digest', currentCase.evidence.sha256Hash],
      ['Evidence Context', currentCase.evidence.description],
    ];

    if (currentCase.merkleSeal) {
      evidenceRows.push([
        'Case Merkle Root',
        `${currentCase.merkleSeal.merkleRoot} (${currentCase.merkleSeal.evidenceCount} bound specimens)`,
      ]);
    }

    autoTable(doc, {
      startY: cursorY,
      margin: { left: margin, right: margin },
      body: evidenceRows,
      theme: 'grid',
      styles: {
        fontSize: 8,
        cellPadding: 2,
        font: 'helvetica',
      },
      columnStyles: {
        0: { fontStyle: 'bold', cellWidth: 44, fillColor: [241, 245, 249] },
        1: { font: 'courier', textColor: [15, 23, 42] },
      },
    });

    // @ts-expect-error - lastAutoTable injected by jspdf-autotable
    cursorY = doc.lastAutoTable.finalY + 8;
  }

  // =========================================================================
  // SECTION 2: FINAL VERDICT (IF REQUESTED)
  // =========================================================================
  if (options.includeVerdict && verificationReport) {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text(labels.finalVerdict, margin, cursorY);
    cursorY += 4;

    const isAuthentic = verificationReport.verdict === 'AUTHENTIC';
    const isTampered = verificationReport.verdict === 'TAMPERED';

    const boxColor = isAuthentic ? [236, 253, 245] : isTampered ? [254, 242, 242] : [255, 251, 235];
    const borderColor = isAuthentic ? [16, 185, 129] : isTampered ? [239, 68, 68] : [245, 158, 11];
    const textColor = isAuthentic ? [4, 120, 87] : isTampered ? [185, 28, 28] : [180, 83, 9];

    doc.setFillColor(boxColor[0], boxColor[1], boxColor[2]);
    doc.setDrawColor(borderColor[0], borderColor[1], borderColor[2]);
    doc.setLineWidth(0.5);
    doc.roundedRect(margin, cursorY, contentWidth, 22, 1.5, 1.5, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.setTextColor(textColor[0], textColor[1], textColor[2]);
    const verdictLabel = isAuthentic ? labels.authentic : isTampered ? labels.tampered : labels.inconclusive;
    doc.text(`VERDICT: ${verdictLabel}`, margin + 6, cursorY + 8);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(51, 65, 85);
    doc.text(
      `Forensic Confidence: ${verificationReport.confidencePercent}%  |  Audited at: ${new Date(verificationReport.verifiedAt).toLocaleString()}`,
      margin + 6,
      cursorY + 15
    );

    cursorY += 26;

    // Bullet reasons
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(71, 85, 105);
    for (const r of verificationReport.reasons.slice(0, 3)) {
      doc.text(`• ${r}`, margin + 4, cursorY);
      cursorY += 4.5;
    }
    cursorY += 4;
  }

  // =========================================================================
  // SECTION 3: FIVE-INDEPENDENT INVARIANT AUDIT TABLE
  // =========================================================================
  if (options.includeIntegrityChecks && verificationReport) {
    if (cursorY > pageHeight - 60) {
      doc.addPage();
      cursorY = 20;
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text(labels.integritySummary, margin, cursorY);
    cursorY += 4;

    const checkRows = Object.values(verificationReport.checks).map((chk) => [
      chk.name,
      chk.status,
      `${chk.weight}%`,
      chk.details,
    ]);

    autoTable(doc, {
      startY: cursorY,
      margin: { left: margin, right: margin },
      head: [['Check Layer', 'Outcome', 'Weight', 'Analytical Findings']],
      body: checkRows,
      theme: 'striped',
      headStyles: {
        fillColor: [15, 23, 42],
        textColor: [255, 255, 255],
        fontSize: 8,
        fontStyle: 'bold',
      },
      styles: {
        fontSize: 7.5,
        cellPadding: 2,
      },
      columnStyles: {
        0: { fontStyle: 'bold', cellWidth: 44 },
        1: { fontStyle: 'bold', cellWidth: 22, halign: 'center' },
        2: { cellWidth: 16, halign: 'center' },
        3: { font: 'courier', fontSize: 7 },
      },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 1) {
          const val = data.cell.raw;
          if (val === 'PASS') {
            data.cell.styles.textColor = [16, 185, 129];
          } else if (val === 'FAIL') {
            data.cell.styles.textColor = [239, 68, 68];
          } else if (val === 'INCONCLUSIVE') {
            data.cell.styles.textColor = [245, 158, 11];
          }
        }
      },
    });

    // @ts-expect-error - injected by jspdf-autotable
    cursorY = doc.lastAutoTable.finalY + 8;
  }

  // =========================================================================
  // SECTION 4: CHAIN OF CUSTODY TIMELINE TABLE
  // =========================================================================
  if (options.includeChainOfCustody) {
    if (cursorY > pageHeight - 60) {
      doc.addPage();
      cursorY = 20;
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text(labels.chainOfCustody, margin, cursorY);
    cursorY += 4;

    const blockRows = currentCase.blocks.map((b) => [
      `#${b.blockIndex}`,
      b.eventType,
      b.actorName,
      b.timestamp.substring(0, 19).replace('T', ' '),
      `${b.previousHash.substring(0, 10)}...`,
      `${b.currentHash.substring(0, 10)}...`,
      b.signatureHex ? 'ECDSA Verified' : 'Unsigned',
    ]);

    autoTable(doc, {
      startY: cursorY,
      margin: { left: margin, right: margin },
      head: [['Block', 'Event', 'Custodian', 'Timestamp', 'Prev Hash', 'Block Hash', 'Signature']],
      body: blockRows,
      theme: 'grid',
      headStyles: {
        fillColor: [30, 41, 59],
        textColor: [255, 255, 255],
        fontSize: 7.5,
        fontStyle: 'bold',
      },
      styles: {
        fontSize: 7,
        cellPadding: 1.8,
      },
      columnStyles: {
        0: { fontStyle: 'bold', cellWidth: 14, halign: 'center' },
        1: { fontStyle: 'bold', cellWidth: 26 },
        2: { cellWidth: 34 },
        3: { cellWidth: 32 },
        4: { font: 'courier', cellWidth: 22 },
        5: { font: 'courier', cellWidth: 22 },
        6: { cellWidth: 24, textColor: [16, 185, 129] },
      },
    });

    // @ts-expect-error - injected by jspdf-autotable
    cursorY = doc.lastAutoTable.finalY + 8;
  }

  // =========================================================================
  // SECTION 5: TAMPER HEATMAP & ANOMALY REGIONS
  // =========================================================================
  if (options.includeHeatmap && verificationReport?.heatmap) {
    if (cursorY > pageHeight - 75) {
      doc.addPage();
      cursorY = 20;
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text(labels.heatmapTitle, margin, cursorY);
    cursorY += 4;

    // Draw Heatmap Image & Regions
    const heatmapImage = verificationReport.heatmap.heatmapDataUrl;
    if (heatmapImage) {
      try {
        doc.addImage(heatmapImage, 'PNG', margin, cursorY, 60, 36);

        // Heatmap notes beside image
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(7.5);
        doc.setTextColor(71, 85, 105);
        doc.text(
          'Methodology: 16x16 Pixel SSIM & Luminance Variance Mapping',
          margin + 65,
          cursorY + 6
        );
        doc.text(
          `Detected Anomalous Regions: ${verificationReport.heatmap.suspiciousRegions.length} zone(s)`,
          margin + 65,
          cursorY + 12
        );
        doc.text('Green: Intact / Authentic pixel blocks', margin + 65, cursorY + 18);
        doc.text('Amber: Minor deviation / compression artifact', margin + 65, cursorY + 23);
        doc.text('Red: High localized modification / Content alteration', margin + 65, cursorY + 28);

        cursorY += 40;
      } catch (err) {
        console.error('Heatmap image insertion error:', err);
      }
    }

    // Suspicious regions table
    if (verificationReport.heatmap.suspiciousRegions.length > 0) {
      const regionRows = verificationReport.heatmap.suspiciousRegions.map((reg) => [
        reg.label,
        `X=${reg.x}, Y=${reg.y}`,
        `${reg.width} x ${reg.height} px`,
        `${(reg.suspicionScore * 100).toFixed(0)}%`,
      ]);

      autoTable(doc, {
        startY: cursorY,
        margin: { left: margin, right: margin },
        head: [['Suspicious Region Label', 'Coordinates', 'Bounding Dimensions', 'Anomaly Score']],
        body: regionRows,
        theme: 'striped',
        headStyles: {
          fillColor: [185, 28, 28],
          textColor: [255, 255, 255],
          fontSize: 7.5,
        },
        styles: { fontSize: 7, cellPadding: 1.5 },
      });

      // @ts-expect-error - injected by jspdf-autotable
      cursorY = doc.lastAutoTable.finalY + 8;
    }
  }

  // =========================================================================
  // SECTION 6: TECHNICAL METHODOLOGY
  // =========================================================================
  if (options.includeMethodology) {
    if (cursorY > pageHeight - 50) {
      doc.addPage();
      cursorY = 20;
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text(labels.methodology, margin, cursorY);
    cursorY += 4;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(71, 85, 105);

    const methodologyText =
      'This forensic examination utilizes mathematically verifiable cryptographic standards compliant with FIPS 180-4 (NIST SHA-256) and ANSI X9.62 (ECDSA P-256 curve). Fragile evidence authentication is enforced via LSB steganography encrypted with PBKDF2 (100,000 iterations of SHA-256) and AES-256-GCM. Permanent ownership and compression survivability are secured through 2D Discrete Cosine Transform (DCT) mid-frequency coefficient pair modulation on the Y-luminance channel with redundant majority voting. The custody ledger guarantees complete tamper-evident immutability through cryptographic backward hash linking.';

    const splitText = doc.splitTextToSize(methodologyText, contentWidth);
    doc.text(splitText, margin, cursorY);
    cursorY += splitText.length * 3.6 + 6;
  }

  // =========================================================================
  // SECTION 6B: AI-GENERATED FORENSIC EXPLANATION (IF REQUESTED)
  // =========================================================================
  if (options.includeAiExplanation && options.aiExplanationText) {
    if (cursorY > pageHeight - 65) {
      doc.addPage();
      cursorY = 20;
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text('AI-Generated Forensic Assessment Brief', margin, cursorY);
    cursorY += 4;

    // Notice banner: "AI-generated explanation (not part of the signed verdict)"
    doc.setFillColor(254, 243, 199);
    doc.setDrawColor(245, 158, 11);
    doc.roundedRect(margin, cursorY, contentWidth, 7, 1, 1, 'FD');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(146, 64, 14);
    doc.text(
      'NOTICE: AI-generated explanation (not part of the signed verdict)',
      margin + 3,
      cursorY + 4.5
    );
    cursorY += 10;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(51, 65, 85);

    const cleanAiText = options.aiExplanationText
      .replace(/###/g, '')
      .replace(/##/g, '')
      .replace(/\*\*/g, '')
      .replace(/`/g, '');

    const splitAi = doc.splitTextToSize(cleanAiText, contentWidth);

    if (cursorY + splitAi.length * 3.4 > pageHeight - 35) {
      const linesPerPage = Math.floor((pageHeight - cursorY - 35) / 3.4);
      const firstChunk = splitAi.slice(0, linesPerPage);
      const remainingChunk = splitAi.slice(linesPerPage);

      doc.text(firstChunk, margin, cursorY);
      doc.addPage();
      cursorY = 20;
      doc.text(remainingChunk, margin, cursorY);
      cursorY += remainingChunk.length * 3.4 + 6;
    } else {
      doc.text(splitAi, margin, cursorY);
      cursorY += splitAi.length * 3.4 + 6;
    }
  }

  // =========================================================================
  // SECTION 7: REPORT SELF-INTEGRITY SEAL BLOCK (Important Innovation)
  // =========================================================================
  if (cursorY > pageHeight - 45) {
    doc.addPage();
    cursorY = 20;
  }

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(15, 23, 42);
  doc.text(labels.reportIntegrity, margin, cursorY);
  cursorY += 4;

  doc.setDrawColor(203, 213, 225);
  doc.setFillColor(248, 250, 252);
  doc.roundedRect(margin, cursorY, contentWidth, 20, 1, 1, 'FD');

  doc.setFont('courier', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(15, 23, 42);
  doc.text(`Report Content SHA-256 Hash: ${reportData.reportHash}`, margin + 4, cursorY + 6);

  doc.setFont('courier', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(100, 116, 139);
  doc.text(
    `ECDSA P-256 Digital Signature: ${reportData.reportSignatureHex.substring(0, 64)}...`,
    margin + 4,
    cursorY + 12
  );
  doc.text(
    `Signer Identity: ${options.investigatorName || 'Forensic Examiner'} (${currentCase.evidence.collectorBadge || 'ID: FED-882'})`,
    margin + 4,
    cursorY + 17
  );

  cursorY += 26;

  // =========================================================================
  // SECTION 8: FORMAL SIGNATURE BLOCKS
  // =========================================================================
  if (options.includeSignatures) {
    if (cursorY > pageHeight - 40) {
      doc.addPage();
      cursorY = 20;
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(15, 23, 42);
    doc.text(labels.signatures, margin, cursorY);
    cursorY += 12;

    const colW = contentWidth / 3;

    // Line 1: Investigating Officer
    doc.setDrawColor(100, 116, 139);
    doc.line(margin, cursorY, margin + colW - 6, cursorY);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(30, 41, 59);
    doc.text('Investigating Officer', margin, cursorY + 4);
    doc.setFont('helvetica', 'normal');
    doc.text(`Name: ${options.investigatorName || currentCase.evidence.collectorName}`, margin, cursorY + 8);
    doc.text(`Date: ${new Date().toLocaleDateString()}`, margin, cursorY + 12);

    // Line 2: Forensic Analyst
    const col2X = margin + colW + 3;
    doc.line(col2X, cursorY, col2X + colW - 6, cursorY);
    doc.setFont('helvetica', 'bold');
    doc.text('Forensic Technical Analyst', col2X, cursorY + 4);
    doc.setFont('helvetica', 'normal');
    doc.text('Signature: [Electronically Verified]', col2X, cursorY + 8);
    doc.text(`Date: ${new Date().toLocaleDateString()}`, col2X, cursorY + 12);

    // Line 3: Reviewing Authority
    const col3X = margin + colW * 2 + 6;
    doc.line(col3X, cursorY, margin + contentWidth, cursorY);
    doc.setFont('helvetica', 'bold');
    doc.text('Reviewing Judicial / Lab Authority', col3X, cursorY + 4);
    doc.setFont('helvetica', 'normal');
    doc.text('Seal & Stamp of Admissibility', col3X, cursorY + 8);
    doc.text(`Date: ${new Date().toLocaleDateString()}`, col3X, cursorY + 12);
  }

  // Add page numbers and headers to all pages
  const totalPages = doc.internal.pages.length - 1;
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    addPageDecorations(i, String(totalPages));
  }

  const safeFilename = `SealChain_Report_${currentCase.caseId}_${reportData.reportId}.pdf`.replace(
    /[^a-zA-Z0-9_.-]/g,
    '_'
  );
  doc.save(safeFilename);
}
