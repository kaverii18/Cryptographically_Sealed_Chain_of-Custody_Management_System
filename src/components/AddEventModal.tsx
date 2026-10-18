/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { PlusCircle, X, Shield, RefreshCw } from 'lucide-react';
import { ActorIdentity, CustodyBlock, CustodyEventType, ForensicCase } from '../types/forensics';
import { createSignedBlock } from '../crypto/webCrypto';

interface AddEventModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentCase: ForensicCase;
  actors: ActorIdentity[];
  onEventAdded: (newBlock: CustodyBlock) => void;
}

export const AddEventModal: React.FC<AddEventModalProps> = ({
  isOpen,
  onClose,
  currentCase,
  actors,
  onEventAdded,
}) => {
  const [eventType, setEventType] = useState<CustodyEventType>('ANALYZED');
  const [selectedActorId, setSelectedActorId] = useState<string>(actors[1]?.id || actors[0]?.id || '');
  const [actionTitle, setActionTitle] = useState('Deep Forensic File Carving & Registry Hive Extraction');
  const [facilityLocation, setFacilityLocation] = useState('State Crime Lab - Digital Evidence Suite 3');
  const [toolOrMethodUsed, setToolOrMethodUsed] = useState('Autopsy 4.19.3 & Volatility Memory/Drive Analyzer');
  const [notes, setNotes] = useState(
    'Conducted carved file recovery for deleted browser databases and encrypted archive artifacts. Write-block verification maintained throughout analysis.'
  );
  const [recipientName, setRecipientName] = useState('');
  const [authorizationReference, setAuthorizationReference] = useState('Forensic Sub-Analysis Order #FSO-2026-78');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const lastBlock = currentCase.blocks[currentCase.blocks.length - 1];
  const nextBlockIndex = lastBlock ? lastBlock.blockIndex + 1 : 0;
  const previousHash = lastBlock ? lastBlock.currentHash : '0000000000000000000000000000000000000000000000000000000000000000';

  const handleEventTypeChange = (type: CustodyEventType) => {
    setEventType(type);
    // Provide smart defaults for forensic workflow
    switch (type) {
      case 'TRANSFERRED':
        setActionTitle('Physical evidence custody transfer to Senior Prosecutor');
        setFacilityLocation('District Attorney Office - Case Intake Desk');
        setToolOrMethodUsed('Tamper-proof evidence transit container #TR-102');
        setNotes('Hand-delivered sealed storage pouch. Barcode seal #SEAL-99801 verified intact prior to signing.');
        setRecipientName('Assistant DA Jennifer Walsh');
        setAuthorizationReference('Court Discovery Order #CD-2026-102');
        break;
      case 'ANALYZED':
        setActionTitle('Deep Forensic File Carving & Registry Hive Extraction');
        setFacilityLocation('State Crime Lab - Digital Evidence Suite 3');
        setToolOrMethodUsed('Autopsy 4.19.3 & Volatility Memory/Drive Analyzer');
        setNotes('Conducted carved file recovery for deleted browser databases and encrypted archive artifacts. Write-block verification maintained.');
        setRecipientName('');
        setAuthorizationReference('Forensic Sub-Analysis Order #FSO-2026-78');
        break;
      case 'STORED':
        setActionTitle('Long-term climate vault storage check-in');
        setFacilityLocation('Central Evidence Warehouse - Vault B, Tier 4');
        setToolOrMethodUsed('RF-shielded Faraday storage locker #L-404');
        setNotes('Re-cataloged and returned to climate-controlled secure vault. Temperature 19°C, humidity 42%.');
        setRecipientName('Evidence Custodian on Duty');
        setAuthorizationReference('Vault Return Slip #VRS-9801');
        break;
      case 'RELEASED':
        setActionTitle('Judicial release of evidence pursuant to court order');
        setFacilityLocation('Superior Court - Evidence Clerk Office');
        setToolOrMethodUsed('Court certified chain release protocol');
        setNotes('Released custody pursuant to final court order. Full cryptographic ledger report exported for trial record.');
        setRecipientName('Clerk of Superior Court');
        setAuthorizationReference('Final Disposition Order #FDO-8839');
        break;
      case 'COLLECTED':
        setActionTitle('Secondary physical specimen recovery');
        setFacilityLocation('Primary Search Scene');
        setToolOrMethodUsed('Anti-static forensic container');
        setNotes('Secondary intake block appended.');
        setRecipientName('');
        setAuthorizationReference('Search Warrant Addendum');
        break;
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      const actor = actors.find((a) => a.id === selectedActorId) || actors[0];
      if (!actor) {
        throw new Error('No valid actor selected.');
      }

      const newBlock = await createSignedBlock({
        blockIndex: nextBlockIndex,
        previousHash,
        eventType,
        actor,
        details: {
          action: actionTitle.trim(),
          facilityLocation: facilityLocation.trim(),
          toolOrMethodUsed: toolOrMethodUsed.trim(),
          notes: notes.trim(),
          recipientName: recipientName.trim(),
          authorizationReference: authorizationReference.trim(),
          departmentOrAgency: actor.agency,
        },
        evidenceId: currentCase.evidence.evidenceId,
        evidenceHash: currentCase.evidence.sha256Hash,
        timestamp: new Date().toISOString(),
      });

      onEventAdded(newBlock);
      onClose();
    } catch (err: unknown) {
      console.error('Failed to append signed custody block:', err);
      const msg = err instanceof Error ? err.message : 'Unknown cryptographic signing error';
      setError(`Failed to sign custody block: ${msg}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="w-full max-w-2xl max-h-[90vh] rounded-xl bg-slate-900 border border-slate-700 shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2 text-cyan-400">
            <PlusCircle className="w-5 h-5" />
            <h2 className="text-base font-semibold text-slate-100">
              Append Custody Event (Block #{nextBlockIndex})
            </h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Form */}
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto p-6 space-y-5">
          {error && (
            <div className="p-3 rounded-lg bg-rose-950/50 border border-rose-600 text-rose-300 text-xs">
              {error}
            </div>
          )}

          {/* Event Type selector */}
          <div>
            <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
              Custody Event Classification *
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {(['TRANSFERRED', 'ANALYZED', 'STORED', 'RELEASED'] as CustodyEventType[]).map(
                (type) => (
                  <button
                    key={type}
                    type="button"
                    onClick={() => handleEventTypeChange(type)}
                    className={`py-2 px-3 text-xs font-mono rounded-md border text-center transition-colors ${
                      eventType === type
                        ? 'bg-cyan-950/80 border-cyan-400 text-cyan-300 font-semibold'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {type}
                  </button>
                )
              )}
            </div>
          </div>

          {/* Actor / Signer */}
          <div>
            <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
              Signing Forensic Custodian / Officer *
            </label>
            <select
              value={selectedActorId}
              onChange={(e) => setSelectedActorId(e.target.value)}
              className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
            >
              {actors.map((actor) => (
                <option key={actor.id} value={actor.id}>
                  {actor.name} — {actor.role} ({actor.agency})
                </option>
              ))}
            </select>
            <p className="text-[11px] text-slate-500 mt-1 font-mono">
              Will cryptographically sign this block using actor’s private Web Crypto ECDSA P-256 key.
            </p>
          </div>

          {/* Action Title */}
          <div>
            <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
              Action Description *
            </label>
            <input
              type="text"
              value={actionTitle}
              onChange={(e) => setActionTitle(e.target.value)}
              required
              className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                Facility / Location
              </label>
              <input
                type="text"
                value={facilityLocation}
                onChange={(e) => setFacilityLocation(e.target.value)}
                className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                Hardware / Tool / Method Used
              </label>
              <input
                type="text"
                value={toolOrMethodUsed}
                onChange={(e) => setToolOrMethodUsed(e.target.value)}
                className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                Recipient / Witness (if transfer)
              </label>
              <input
                type="text"
                value={recipientName}
                onChange={(e) => setRecipientName(e.target.value)}
                placeholder="Optional recipient name"
                className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
                Legal / Authorization Reference
              </label>
              <input
                type="text"
                value={authorizationReference}
                onChange={(e) => setAuthorizationReference(e.target.value)}
                placeholder="Court order, work order, warrant #"
                className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono uppercase text-slate-400 mb-1.5">
              Custody Examination Notes *
            </label>
            <textarea
              rows={3}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              required
              className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded-md text-slate-100 focus:outline-none focus:border-cyan-500 resize-none"
            />
          </div>

          {/* Cryptographic Link Preview */}
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5 text-xs font-mono">
            <div className="flex items-center justify-between text-slate-400">
              <span>Parent Block: #{lastBlock ? lastBlock.blockIndex : 'None'}</span>
              <span className="text-cyan-400">Linking to Head</span>
            </div>
            <div className="text-[11px] text-slate-300 break-all">
              <span className="text-slate-500">Previous Hash:</span> {previousHash}
            </div>
          </div>

          {/* Footer Submit */}
          <div className="pt-2 flex items-center justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-white transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-5 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md transition-colors flex items-center gap-2 shadow-md shadow-cyan-950"
            >
              {isSubmitting ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Signing Block...</span>
                </>
              ) : (
                <>
                  <Shield className="w-3.5 h-3.5" />
                  <span>Sign & Append to Ledger</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
