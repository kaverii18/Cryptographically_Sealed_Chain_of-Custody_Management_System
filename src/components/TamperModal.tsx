/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { AlertOctagon, X, ShieldAlert, Cpu, ArrowRight } from 'lucide-react';
import { CustodyBlock, ForensicCase } from '../types/forensics';

interface TamperModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentCase: ForensicCase;
  onApplyTamper: (
    blockIndex: number,
    tamperType: 'ACTOR' | 'TIMESTAMP' | 'NOTES' | 'EVIDENCE_HASH' | 'CURRENT_HASH' | 'PREVIOUS_HASH',
    customValue?: string
  ) => void;
}

export const TamperModal: React.FC<TamperModalProps> = ({
  isOpen,
  onClose,
  currentCase,
  onApplyTamper,
}) => {
  const [selectedBlockIndex, setSelectedBlockIndex] = useState<number>(
    currentCase.blocks.length > 1 ? 1 : 0
  );
  const [tamperType, setTamperType] = useState<
    'ACTOR' | 'TIMESTAMP' | 'NOTES' | 'EVIDENCE_HASH' | 'CURRENT_HASH' | 'PREVIOUS_HASH'
  >('NOTES');
  const [customValue, setCustomValue] = useState<string>('');

  if (!isOpen) return null;

  const targetBlock: CustodyBlock | undefined = currentCase.blocks.find(
    (b) => b.blockIndex === selectedBlockIndex
  );

  const getTamperDescription = () => {
    switch (tamperType) {
      case 'ACTOR':
        return 'Alters the recorded investigator / custodian name without a valid private key. ECDSA P-256 signature verification will fail immediately.';
      case 'TIMESTAMP':
        return 'Modifies the recorded timestamp (e.g., backdating evidence acquisition). The recomputed SHA-256 hash will not match the signed payload.';
      case 'NOTES':
        return 'Edits forensic findings or custody notes (e.g. altering chain of custody details). Breaks both canonical SHA-256 hash and ECDSA signature.';
      case 'EVIDENCE_HASH':
        return 'Swaps the referenced digital evidence SHA-256 hash with an altered hash, simulating substitution of seized files.';
      case 'CURRENT_HASH':
        return 'Corrupts the stored block hash directly, causing subsequent blocks’ previous-hash pointers and hash recomputation to fail.';
      case 'PREVIOUS_HASH':
        return 'Corrupts the previous-hash pointer, breaking the Merkle-linked blockchain continuity with the preceding block.';
    }
  };

  const handleApply = () => {
    onApplyTamper(selectedBlockIndex, tamperType, customValue || undefined);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="w-full max-w-xl rounded-xl bg-slate-900 border border-slate-700 shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 bg-rose-950/40 border-b border-rose-900/50 flex items-center justify-between">
          <div className="flex items-center gap-2 text-rose-400">
            <AlertOctagon className="w-5 h-5" />
            <h2 className="text-base font-semibold text-slate-100">
              Forensic Tampering Simulation
            </h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5">
          <p className="text-xs text-slate-300 leading-relaxed">
            This laboratory tool intentionally injects unauthorized modifications into a block without re-signing it.
            Use this to demonstrate how <strong className="text-cyan-400">SealChain</strong> immediately detects fraudulent edits,
            invalidates digital signatures, and triggers a cascading <strong className="text-rose-400">BROKEN LINK</strong> alert on that block and all subsequent blocks.
          </p>

          {/* Select Block */}
          <div>
            <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
              Target Custody Block to Compromise
            </label>
            <select
              value={selectedBlockIndex}
              onChange={(e) => setSelectedBlockIndex(Number(e.target.value))}
              className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 font-mono focus:outline-none focus:border-rose-500"
            >
              {currentCase.blocks.map((block) => (
                <option key={block.blockIndex} value={block.blockIndex}>
                  Block #{block.blockIndex} [{block.eventType}] — {block.actorName} (
                  {block.timestamp.substring(11, 19)} UTC)
                </option>
              ))}
            </select>
          </div>

          {/* Tamper Vector */}
          <div>
            <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
              Adversarial Tamper Vector
            </label>
            <div className="grid grid-cols-2 gap-2 text-xs">
              {[
                { type: 'NOTES', label: 'Modify Case Notes / Findings' },
                { type: 'ACTOR', label: 'Impersonate / Change Actor' },
                { type: 'TIMESTAMP', label: 'Backdate Timestamp' },
                { type: 'EVIDENCE_HASH', label: 'Substitute Evidence Hash' },
                { type: 'CURRENT_HASH', label: 'Corrupt Block Hash' },
                { type: 'PREVIOUS_HASH', label: 'Break Previous-Hash Pointer' },
              ].map((item) => (
                <button
                  key={item.type}
                  type="button"
                  onClick={() =>
                    setTamperType(
                      item.type as
                        | 'ACTOR'
                        | 'TIMESTAMP'
                        | 'NOTES'
                        | 'EVIDENCE_HASH'
                        | 'CURRENT_HASH'
                        | 'PREVIOUS_HASH'
                    )
                  }
                  className={`p-2.5 text-left rounded-md border font-mono transition-colors ${
                    tamperType === item.type
                      ? 'bg-rose-950/60 border-rose-500 text-rose-200'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                  }`}
                >
                  {item.label}
                </button>
              ))}
            </div>
          </div>

          {/* Target Block Current State */}
          {targetBlock && (
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono space-y-1">
              <span className="text-slate-500 uppercase block text-[10px]">
                Current Block #{targetBlock.blockIndex} Values:
              </span>
              <div className="text-slate-300 truncate">
                <span className="text-slate-500">Actor:</span> {targetBlock.actorName}
              </div>
              <div className="text-slate-300 truncate">
                <span className="text-slate-500">Notes:</span> {targetBlock.details.notes}
              </div>
              <div className="text-slate-300 truncate">
                <span className="text-slate-500">Hash:</span> {targetBlock.currentHash.substring(0, 24)}...
              </div>
            </div>
          )}

          {/* Explanation Box */}
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-start gap-2 text-xs text-slate-300">
            <Cpu className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-cyan-300 block mb-0.5">Cryptographic Consequence</span>
              <p className="text-slate-400 leading-normal">{getTamperDescription()}</p>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 bg-slate-950 border-t border-slate-800 flex items-center justify-between">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-white transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleApply}
            className="px-4 py-2 text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 rounded-md transition-colors flex items-center gap-1.5 shadow-md shadow-rose-950"
          >
            <ShieldAlert className="w-4 h-4" />
            <span>Inject Tampering & Check Verification</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
