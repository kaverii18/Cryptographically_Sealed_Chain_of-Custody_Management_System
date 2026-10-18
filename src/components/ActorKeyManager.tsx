/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Key, Shield, UserPlus, Copy, Check, Fingerprint, RefreshCw } from 'lucide-react';
import { ActorIdentity } from '../types/forensics';
import { generateECDSAKeyPair } from '../crypto/webCrypto';
import { saveActors } from '../services/storageService';

interface ActorKeyManagerProps {
  actors: ActorIdentity[];
  onActorsUpdated: (updatedActors: ActorIdentity[]) => void;
}

export const ActorKeyManager: React.FC<ActorKeyManagerProps> = ({
  actors,
  onActorsUpdated,
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);

  // New Actor Form
  const [name, setName] = useState('');
  const [role, setRole] = useState('Forensic Digital Investigator');
  const [agency, setAgency] = useState('State Bureau of Investigation');
  const [badgeNumber, setBadgeNumber] = useState('SBI-552');

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(id);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleGenerateActor = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    setIsGenerating(true);
    try {
      const keyPair = await generateECDSAKeyPair();
      const newActor: ActorIdentity = {
        id: `actor-${Date.now()}`,
        name: name.trim(),
        role: role.trim(),
        agency: agency.trim(),
        badgeNumber: badgeNumber.trim(),
        publicKeyJwk: keyPair.publicKeyJwk,
        privateKeyJwk: keyPair.privateKeyJwk,
      };

      const updated = [...actors, newActor];
      saveActors(updated);
      onActorsUpdated(updated);

      setName('');
      setShowAddForm(false);
    } catch (err) {
      console.error('Failed to generate officer keypair:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-8 px-4 sm:px-6 space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-2">
            <span>PUBLIC KEY INFRASTRUCTURE</span>
            <span aria-hidden="true">·</span>
            <span>NIST P-256 ECDSA IDENTITIES</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-100">
            Forensic Officers & Cryptographic Keys
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Digital custody signatures are generated using client-side Web Crypto ECDSA (secp256r1) key pairs.
          </p>
        </div>

        <button
          onClick={() => setShowAddForm(!showAddForm)}
          className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md transition-colors flex items-center gap-2 self-start sm:self-auto shadow-sm shadow-cyan-950"
        >
          <UserPlus className="w-4 h-4" />
          <span>Register New Officer</span>
        </button>
      </div>

      {/* Add New Officer Drawer */}
      {showAddForm && (
        <form
          onSubmit={handleGenerateActor}
          className="p-6 rounded-xl bg-slate-900 border border-slate-700 shadow-xl space-y-4"
        >
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200 uppercase font-mono tracking-wider">
              Generate Officer Cryptographic Identity
            </h3>
            <span className="text-xs text-cyan-400 font-mono">
              Web Crypto P-256 Keypair
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1">
                Full Name & Rank *
              </label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Det. Sarah Connor"
                className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded text-slate-100 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1">
                Forensic Role / Assignment
              </label>
              <input
                type="text"
                value={role}
                onChange={(e) => setRole(e.target.value)}
                placeholder="e.g. Lead Malware Analyst"
                className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded text-slate-100 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1">
                Agency / Department
              </label>
              <input
                type="text"
                value={agency}
                onChange={(e) => setAgency(e.target.value)}
                placeholder="e.g. Cyber Crimes Taskforce"
                className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded text-slate-100 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1">
                Badge / Serial Number
              </label>
              <input
                type="text"
                value={badgeNumber}
                onChange={(e) => setBadgeNumber(e.target.value)}
                placeholder="e.g. CCT-901"
                className="w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setShowAddForm(false)}
              className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isGenerating}
              className="px-4 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded flex items-center gap-1.5"
            >
              {isGenerating ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Generating Keys...</span>
                </>
              ) : (
                <>
                  <Key className="w-3.5 h-3.5" />
                  <span>Generate Keypair & Save</span>
                </>
              )}
            </button>
          </div>
        </form>
      )}

      {/* Officers Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {actors.map((actor) => (
          <div
            key={actor.id}
            className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4 hover:border-slate-700 transition-colors"
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400">
                  <Shield className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-slate-100">{actor.name}</h3>
                  <div className="text-xs text-slate-400">
                    {actor.role}
                  </div>
                </div>
              </div>
              <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950/70 border border-cyan-800 px-2 py-0.5 rounded">
                {actor.badgeNumber}
              </span>
            </div>

            <div className="text-xs text-slate-400 font-mono">
              <span className="text-slate-500">Agency:</span> {actor.agency}
            </div>

            {/* Public Key JWK Coordinates */}
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 space-y-2 text-xs font-mono">
              <div className="flex items-center justify-between text-slate-400">
                <span className="flex items-center gap-1 text-[11px] uppercase">
                  <Fingerprint className="w-3.5 h-3.5 text-cyan-400" />
                  <span>ECDSA P-256 Public Coordinates</span>
                </span>
                <button
                  onClick={() =>
                    handleCopy(JSON.stringify(actor.publicKeyJwk, null, 2), `jwk-${actor.id}`)
                  }
                  className="text-[11px] text-slate-400 hover:text-cyan-400 flex items-center gap-1"
                >
                  {copiedKey === `jwk-${actor.id}` ? (
                    <Check className="w-3 h-3 text-emerald-400" />
                  ) : (
                    <Copy className="w-3 h-3" />
                  )}
                  <span>Copy JWK</span>
                </button>
              </div>

              <div className="space-y-1 text-[11px]">
                <div className="text-slate-400 truncate">
                  <span className="text-slate-500">X:</span> {String(actor.publicKeyJwk.x)}
                </div>
                <div className="text-slate-400 truncate">
                  <span className="text-slate-500">Y:</span> {String(actor.publicKeyJwk.y)}
                </div>
              </div>
            </div>

            <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono">
              <span>Curve: P-256</span>
              <span className="text-emerald-400">Keypair Ready for Signing</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
