/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { StructuredForensicDataForAi } from '../types/forensics';

/**
 * Generates an authoritative, mathematically grounded rule-based forensic explanation
 * when the external Gemini API is unreachable, rate-limited, or unconfigured.
 */
export function generateRuleBasedForensicExplanation(
  data: StructuredForensicDataForAi,
  language: 'en' | 'mr' = 'en'
): string {
  const isMr = language === 'mr';

  const checkSummaries = [
    {
      name: isMr ? 'फाइल हॅश पडताळणी (NIST SHA-256)' : 'File Hash (NIST SHA-256)',
      status: data.checks.fileHash.status,
      reason: data.checks.fileHash.reason,
      explanation:
        data.checks.fileHash.status === 'PASS'
          ? isMr
            ? 'मूळ पुराव्याच्या प्रत्येक बाइटशी डिजिटल हॅश तंतोतंत जुळत आहे. बाइट पातळीवर कोणताही फेरबदल झालेला नाही.'
            : 'Exact byte-for-byte match with the intake record. No bit-level alterations detected in the raw stream.'
          : isMr
          ? 'हॅश न जुळणे हे सूचित करते की फाइल संकुचित (compressed), पुन्हा जतन (re-saved) किंवा संपादित केली गेली आहे.'
          : 'Cryptographic hash mismatch indicates file modification, re-compression, or pixel manipulation after initial intake.',
    },
    {
      name: isMr ? 'लपवलेला डिजिटल सील (LSB Steganography + AES-GCM)' : 'Hidden Seal (LSB + AES-256-GCM)',
      status: data.checks.hiddenSeal.status,
      reason: data.checks.hiddenSeal.reason,
      explanation:
        data.checks.hiddenSeal.status === 'PASS'
          ? isMr
            ? 'गुपित पेलोड सुरक्षितपणे डिक्रिप्ट झाला. AES-GCM प्रमाणीकरण टॅग अक्षुण्ण आहे.'
            : 'Encrypted fragile payload successfully decrypted. AES-GCM authentication tag verified without corruption.'
          : isMr
          ? 'एलएसबी पेलोड दूषित किंवा नष्ट झाला आहे. जेपीईजी कॉम्प्रेशन किंवा पिक्सेल पॅचिंगमुळे हे होऊ शकते.'
          : 'Fragile LSB bits destroyed or corrupted. Common with JPEG compression, spatial resizing, or localized editing.',
    },
    {
      name: isMr ? 'डिजिटल स्वाक्षरी (ECDSA P-256)' : 'Digital Signature (ECDSA P-256)',
      status: data.checks.signature.status,
      reason: data.checks.signature.reason,
      explanation:
        data.checks.signature.status === 'PASS'
          ? isMr
            ? 'अधिकारी/विश्लेषकाच्या अधिकृत पब्लिक की द्वारे स्वाक्षरी प्रमाणित झाली आहे.'
            : 'Signed with the authorized forensic examiner’s private key and mathematically validated against their registered public key.'
          : isMr
          ? 'डिजिटल स्वाक्षरी अवैध किंवा गहाळ आहे. सील अधिकृत अधिकाऱ्याने स्वाक्षरी केलेला नाही.'
          : 'Cryptographic signature invalid or unverified. Origin authentication cannot be established.',
    },
    {
      name: isMr ? 'लेजर साखळी अखंडता (Hash-Linked Timeline)' : 'Ledger Integrity (Hash-Linked Blockchain)',
      status: data.checks.ledgerIntegrity.status,
      reason: data.checks.ledgerIntegrity.reason,
      explanation:
        data.checks.ledgerIntegrity.status === 'PASS'
          ? isMr
            ? 'कस्टडी लेजरमधील सर्व ब्लॉक्स अखंडित आहेत; बॅकवर्ड हॅश पॉइंटर्स आणि स्वाक्षऱ्या सुसंगत आहेत.'
            : 'All custody blocks are unbroken; previous-hash pointers and sequential timestamps maintain perfect continuity.'
          : isMr
          ? 'लेजर साखळीत खंड आढळला आहे! ऐतिहासिक नोंद किंवा कस्टडी इव्हेंटमध्ये बेकायदेशीर छेडछाड झाली आहे.'
          : 'Broken link detected in custody chain! Historical blocks or audit records have been manipulated.',
    },
    {
      name: isMr ? 'रोबस्ट वॉटरमार्क (2D-DCT Y-Luminance)' : 'Robust Watermark (2D-DCT Y-Luminance)',
      status: data.checks.robustWatermark.status,
      reason: data.checks.robustWatermark.reason,
      explanation:
        data.checks.robustWatermark.status === 'PASS'
          ? isMr
            ? '८x८ फ्रिक्वेन्सी डोमेन वॉटरमार्क सुरक्षित राहिला आहे (बहुमत मतदानाने पुनर्प्राप्त).'
            : 'Mid-frequency DCT watermark coefficients preserved across blocks with high bit-match rate.'
          : isMr
          ? 'वॉटरमार्क नष्ट किंवा अत्यंत दुर्बल झाला आहे, जे गंभीर छेडछाड किंवा क्रॉपिंग दर्शवते.'
          : 'Watermark degraded or absent, indicating aggressive spatial cropping or multi-generation re-encoding.',
    },
  ];

  if (isMr) {
    return `### सीलचेन फॉरेन्सिक विश्लेषण अहवाल (नियम-आधारित इंजिन)
*टीप: हा निष्कर्ष गणितीय पडताळणी इंजिनद्वारे काढला गेला आहे. एआय केवळ डेटा स्पष्ट करतो.*

**अंतिम निर्णय:** ${
      data.verdict === 'AUTHENTIC'
        ? '✅ अस्सल (AUTHENTIC) — न्यायालयात ग्राह्य'
        : data.verdict === 'TAMPERED'
        ? '❌ छेडछाड झालेली (TAMPERED) — पुराव्याची विश्वासार्हता भंग पावली आहे'
        : '⚠️ अनिर्णित (INCONCLUSIVE) — तांत्रिक फेरबदल आढळले आहेत'
    }
**विश्वासार्हता गुण:** ${data.confidencePercent}%
**तपासलेले पुरावा आयडी:** \`${data.evidenceId}\` (प्रकरण: \`${data.caseId}\`)

---

#### १. पाच स्वतंत्र पडताळण्यांचे सविस्तर निष्कर्ष:
${checkSummaries.map((c) => `- **${c.name}**: [${c.status}] — ${c.explanation}`).join('\n')}

---

#### २. छेडछाड व संशयित भागांचे विश्लेषण:
${
  data.suspiciousRegions.length > 0
    ? `तपासणीमध्ये **${data.suspiciousRegions.length} संशयास्पद भाग (Regions)** आढळले आहेत:` +
      '\n' +
      data.suspiciousRegions
        .map(
          (r) =>
            `  • **${r.label}**: स्थान (X=${r.x}, Y=${r.y}), आकार (${r.width}x${r.height} px), संशय गुण: ${(r.anomalyScore * 100).toFixed(0)}%`
        )
        .join('\n')
    : `कोणतेही संशयास्पद किंवा संपादित भाग आढळले नाहीत. पिक्सेल विचलनाचा दर सामान्य आहे.`
}

---

#### ३. तपास अधिकाऱ्यासाठी पुढील शिफारशी:
${
  data.verdict === 'AUTHENTIC'
    ? `१. हा पुरावा आणि लेजर साखळी न्यायालयात सादर करण्यासाठी पूर्णपणे ग्राह्य आहे.
२. डिजिटल स्वाक्षरीसह औपचारिक पीडीएफ अहवाल डाऊनलोड करा.
३. पुरावा हार्ड ड्राईव्ह अधिकृत कस्टडी लॉकरमध्ये सुरक्षित ठेवा.`
    : data.verdict === 'TAMPERED'
    ? `१. **तातडीने तपास करा**: पुरावा ज्या कस्टोडियनच्या ताब्यात होता, त्यांची चौकशी करा.
२. संशयित भागांवर (उदा. क्लोन-पॅचिंग किंवा मजकूर पुसणे) मायक्रो-फॉरेन्सिक विश्लेषण करा.
३. कस्टडी लेजरमधील स्वाक्षऱ्या आणि ब्लॉक बदल तपासण्यासाठी लेजर ऑडिट लॉग तपासा.`
    : `१. फाइल जेपीईजी कॉम्प्रेशन किंवा मेसेजिंग ॲप (उदा. व्हॉट्सॲप) द्वारे पाठवली गेली आहे का ते तपासा.
२. मूळ रॉ (RAW/PNG) पुरावा पुन्हा गोळा करा.`
}

---
*मर्यादा स्पष्टीकरण: हा अहवाल सीलचेनच्या इन-ब्राउझर वेब क्रिप्टो नियमांवर आधारित आहे. अंतिम निर्णय फॉरेन्सिक तज्ज्ञ व न्यायालयाचा राहील.*`;
  }

  // English fallback
  return `### SealChain Forensic Intelligence Summary (Deterministic Engine)
*Note: Findings are calculated deterministically by the cryptographic decision engine. The AI assistant contextualizes the mathematical results.*

**Final Admissibility Verdict:** ${
    data.verdict === 'AUTHENTIC'
      ? '✅ AUTHENTIC — COURT ADMISSIBLE'
      : data.verdict === 'TAMPERED'
      ? '❌ TAMPERED — INTEGRITY BREACH DETECTED'
      : '⚠️ INCONCLUSIVE — NON-MALICIOUS RE-ENCODING'
  }
**Confidence Score:** ${data.confidencePercent}%
**Target Specimen:** \`${data.evidenceId}\` (Case: \`${data.caseId}\`)

---

#### 1. Detailed Breakdown of 5 Independent Verification Checks:
${checkSummaries.map((c) => `- **${c.name}**: [${c.status}] — ${c.explanation}`).join('\n')}

---

#### 2. Tamper Localization & Heatmap Findings:
${
  data.suspiciousRegions.length > 0
    ? `Spatial analysis isolated **${data.suspiciousRegions.length} anomalous region(s)** with structural luminance & SSIM degradation:` +
      '\n' +
      data.suspiciousRegions
        .map(
          (r) =>
            `  • **${r.label}**: Coordinates (X=${r.x}, Y=${r.y}), Bounding Box (${r.width}x${r.height} px), Anomaly Score: ${(r.anomalyScore * 100).toFixed(0)}%`
        )
        .join('\n')
    : `No anomalous pixel groupings detected. Structural similarity across all 16x16 macroblocks remains within acceptable tolerances.`
}

---

#### 3. Actionable Next Steps for Investigating Officers:
${
  data.verdict === 'AUTHENTIC'
    ? `1. Proceed with formal judicial filing. The cryptographic custody chain satisfies Federal Rule of Evidence 901/902 standards.
2. Export the court-admissible PDF report with the cryptographic self-integrity seal.
3. Preserve the primary physical storage specimen in an RF-shielded evidence vault.`
    : data.verdict === 'TAMPERED'
    ? `1. **Investigate Chain of Custody**: Review the custody timeline to isolate which custodian had physical possession when the alteration occurred.
2. **Subpoena Original Source**: Request bitstream forensic images directly from original capture hardware.
3. **Correlate Tampered Coordinates**: Examine what visual elements were located at the identified anomalous coordinates (e.g. altered timestamps, license plates, weapon removal).`
    : `1. Verify whether the suspect image underwent intermediate re-encoding (e.g. messaging apps, cloud thumbnails).
2. Attempt recovery of original lossless PNG/TIFF camera output.
3. Cross-reference the robust DCT watermark match percentage (resilient to mild compression) with the brittle LSB seal.`
}

---
*Boundary & Authority Notice: SealChain’s explanation engine explains cryptographic and visual metrics; it does not replace the judicial trier of fact.*`;
}
