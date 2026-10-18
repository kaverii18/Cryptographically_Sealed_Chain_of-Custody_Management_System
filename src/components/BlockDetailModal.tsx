/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { X, Copy, Check, Key, ShieldCheck, FileCode } from 'lucide-react';
import { CustodyBlock } from '../types/forensics';
import { getCanonicalBlockPayload } from '../crypto/webCrypto';

interface BlockDetailModalProps {
  block: CustodyBlock | null;
  onClose: () => void;
}

export const BlockDetailModal: React.FC<BlockDetailModalProps> = ({ block, onClose }) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  if (!block) return null;

  const canonicalPayload = getCanonicalBlockPayload(block);

  const handleCopy = (text: string, keyName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(keyName);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm">
      <div className="w-full max-w-3xl max-h-[90vh] rounded-xl bg-slate-900 border border-slate-700 shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <Key className="w-5 h-5 text-cyan-400" />
            <div>
              <h2 className="text-base font-semibold text-slate-100">
                Cryptographic Block Inspection: #{block.blockIndex} [{block.eventType}]
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Sealed: {block.timestamp}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6 text-xs">
          {/* Hashes Row */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-mono uppercase text-slate-400 text-[11px]">
                  Previous Block Pointer Hash
                </span>
                <button
                  onClick={() => handleCopy(block.previousHash, 'prevHash')}
                  className="text-slate-400 hover:text-cyan-400 font-mono text-[11px] flex items-center gap-1"
                >
                  {copiedKey === 'prevHash' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>Copy</span>
                </button>
              </div>
              <div className="p-2 rounded bg-slate-900/90 font-mono text-slate-300 break-all select-all text-[11px] border border-slate-800/80">
                {block.previousHash}
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-mono uppercase text-cyan-400 text-[11px]">
                  Current Block Hash (SHA-256)
                </span>
                <button
                  onClick={() => handleCopy(block.currentHash, 'currHash')}
                  className="text-slate-400 hover:text-cyan-400 font-mono text-[11px] flex items-center gap-1"
                >
                  {copiedKey === 'currHash' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>Copy</span>
                </button>
              </div>
              <div className="p-2 rounded bg-cyan-950/40 font-mono text-cyan-300 break-all select-all text-[11px] border border-cyan-800/50">
                {block.currentHash}
              </div>
            </div>
          </div>

          {/* ECDSA Digital Signature */}
          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span className="font-mono uppercase text-emerald-400 text-[11px] font-semibold">
                  ECDSA P-256 Digital Signature (Hex Encoding)
                </span>
              </div>
              <button
                onClick={() => handleCopy(block.signatureHex, 'sig')}
                className="text-slate-400 hover:text-cyan-400 font-mono text-[11px] flex items-center gap-1"
              >
                {copiedKey === 'sig' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>Copy Signature</span>
              </button>
            </div>
            <div className="p-2 rounded bg-slate-900 font-mono text-emerald-300 break-all select-all text-[11px] border border-slate-800">
              {block.signatureHex}
            </div>
            <div className="flex items-center justify-between text-slate-400 font-mono text-[10px] pt-1">
              <span>Curve: NIST P-256 (secp256r1)</span>
              <span>Signer Fingerprint: {block.actorPublicKeyFingerprint}</span>
            </div>
          </div>

          {/* Actor Public Key JWK */}
          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Key className="w-4 h-4 text-amber-400" />
                <span className="font-mono uppercase text-amber-300 text-[11px] font-semibold">
                  Signer ECDSA Public Key (JWK Parameters)
                </span>
              </div>
              <button
                onClick={() => handleCopy(JSON.stringify(block.actorPublicKeyJwk, null, 2), 'jwk')}
                className="text-slate-400 hover:text-cyan-400 font-mono text-[11px] flex items-center gap-1"
              >
                {copiedKey === 'jwk' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>Copy JWK</span>
              </button>
            </div>
            <pre className="p-3 rounded bg-slate-900 font-mono text-slate-300 text-[11px] overflow-x-auto border border-slate-800">
              {JSON.stringify(block.actorPublicKeyJwk, null, 2)}
            </pre>
          </div>

          {/* Canonical Payload */}
          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-cyan-400" />
                <span className="font-mono uppercase text-slate-300 text-[11px] font-semibold">
                  Canonical Serialized Payload (Signature Base & Hash Target)
                </span>
              </div>
              <button
                onClick={() => handleCopy(canonicalPayload, 'payload')}
                className="text-slate-400 hover:text-cyan-400 font-mono text-[11px] flex items-center gap-1"
              >
                {copiedKey === 'payload' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>Copy Payload</span>
              </button>
            </div>
            <pre className="p-3 rounded bg-slate-900 font-mono text-slate-300 text-[11px] overflow-x-auto whitespace-pre-wrap break-all border border-slate-800">
              {canonicalPayload}
            </pre>
            <p className="text-[10px] text-slate-500 font-mono">
              Deterministic string representation ensures bit-exact reproducible hashing across any environment.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 bg-slate-950 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-md transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
