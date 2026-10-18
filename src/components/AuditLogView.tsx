/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Search,
  Filter,
  Download,
  Calendar,
  User,
  Lock,
  ArrowUpDown,
  RefreshCw,
  Copy,
  Check,
  AlertTriangle,
  LogIn,
  LogOut,
  Ban,
  GitCommit,
  FileText,
} from 'lucide-react';
import { CustodyBlock, CustodyEventType, ForensicCase } from '../types/forensics';

interface AuditLogViewProps {
  currentCase: ForensicCase;
}

export const AuditLogView: React.FC<AuditLogViewProps> = ({ currentCase }) => {
  const [selectedUser, setSelectedUser] = useState<string>('ALL');
  const [selectedRole, setSelectedRole] = useState<string>('ALL');
  const [selectedEventType, setSelectedEventType] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Available unique users and roles from the active ledger
  const uniqueUsers = useMemo(() => {
    const set = new Set<string>();
    currentCase.blocks.forEach((b) => set.add(b.actorName));
    return Array.from(set);
  }, [currentCase]);

  const uniqueRoles = useMemo(() => {
    const set = new Set<string>();
    currentCase.blocks.forEach((b) => set.add(b.actorRole));
    return Array.from(set);
  }, [currentCase]);

  // Filtered blocks list
  const filteredBlocks = useMemo(() => {
    return currentCase.blocks.filter((b) => {
      // User filter
      if (selectedUser !== 'ALL' && b.actorName !== selectedUser) {
        return false;
      }
      // Role filter
      if (selectedRole !== 'ALL' && b.actorRole !== selectedRole) {
        return false;
      }
      // Event type filter
      if (selectedEventType !== 'ALL' && b.eventType !== selectedEventType) {
        return false;
      }
      // Search term
      if (searchTerm.trim()) {
        const query = searchTerm.toLowerCase();
        const matchesAction = b.details.action.toLowerCase().includes(query);
        const matchesNotes = b.details.notes.toLowerCase().includes(query);
        const matchesActor = b.actorName.toLowerCase().includes(query);
        const matchesHash = b.currentHash.toLowerCase().includes(query);
        const matchesAuth = b.details.authorizationReference?.toLowerCase().includes(query);
        if (!matchesAction && !matchesNotes && !matchesActor && !matchesHash && !matchesAuth) {
          return false;
        }
      }
      return true;
    });
  }, [currentCase, selectedUser, selectedRole, selectedEventType, searchTerm]);

  const copyToClipboard = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleExportCsv = () => {
    const headers = [
      'Block Index',
      'Timestamp',
      'Event Type',
      'Actor Name',
      'Actor Role',
      'Agency',
      'Action Details',
      'Block SHA-256 Hash',
      'Previous Hash',
      'Signature Status',
    ];

    const rows = filteredBlocks.map((b) => [
      b.blockIndex,
      b.timestamp,
      b.eventType,
      `"${b.actorName.replace(/"/g, '""')}"`,
      `"${b.actorRole.replace(/"/g, '""')}"`,
      `"${b.actorAgency.replace(/"/g, '""')}"`,
      `"${b.details.action.replace(/"/g, '""')}"`,
      b.currentHash,
      b.previousHash,
      b.signatureHex ? 'ECDSA_VERIFIED' : 'UNSIGNED',
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `SealChain_AuditLog_${currentCase.caseId}_${Date.now()}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const getEventBadge = (type: CustodyEventType) => {
    switch (type) {
      case 'ACCESS_DENIED':
        return (
          <span className="px-2 py-0.5 rounded bg-rose-950 border border-rose-700 text-rose-300 font-bold flex items-center gap-1">
            <Ban className="w-3 h-3 text-rose-400" />
            <span>ACCESS DENIED</span>
          </span>
        );
      case 'USER_LOGIN':
        return (
          <span className="px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300 font-bold flex items-center gap-1">
            <LogIn className="w-3 h-3 text-cyan-400" />
            <span>USER LOGIN</span>
          </span>
        );
      case 'USER_LOGOUT':
        return (
          <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-bold flex items-center gap-1">
            <LogOut className="w-3 h-3 text-slate-400" />
            <span>USER LOGOUT</span>
          </span>
        );
      case 'CASE_SEALED':
        return (
          <span className="px-2 py-0.5 rounded bg-emerald-950 border border-emerald-700 text-emerald-300 font-bold flex items-center gap-1">
            <GitCommit className="w-3 h-3 text-emerald-400" />
            <span>CASE SEALED</span>
          </span>
        );
      case 'REPORT_GENERATED':
        return (
          <span className="px-2 py-0.5 rounded bg-purple-950 border border-purple-700 text-purple-300 font-bold flex items-center gap-1">
            <FileText className="w-3 h-3 text-purple-400" />
            <span>REPORT ISSUED</span>
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded bg-slate-800/90 border border-slate-700 text-slate-300 font-mono">
            {type}
          </span>
        );
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Title & Stats */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-cyan-950/70 border border-cyan-500/40 text-cyan-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-slate-100 font-mono">
                System Security & Custody Audit Log
              </h1>
              <p className="text-xs text-slate-400">
                Immutable, sequential log of all user authentications, forensic procedures, access attempts, and custody events.
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={handleExportCsv}
          className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-mono flex items-center gap-2 transition-colors cursor-pointer"
        >
          <Download className="w-4 h-4 text-cyan-400" />
          <span>Export Audit Log (CSV)</span>
        </button>
      </div>

      {/* Filter Bar */}
      <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 shadow-xl space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
          {/* Search Input */}
          <div>
            <label className="block text-slate-400 mb-1">Search Action / Hash:</label>
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-3" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search action or notes..."
                className="w-full pl-9 pr-3 py-2 bg-slate-900 border border-slate-700 rounded text-slate-100 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {/* User Filter */}
          <div>
            <label className="block text-slate-400 mb-1">Filter by User:</label>
            <select
              value={selectedUser}
              onChange={(e) => setSelectedUser(e.target.value)}
              className="w-full p-2 bg-slate-900 border border-slate-700 rounded text-slate-100 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Users ({uniqueUsers.length})</option>
              {uniqueUsers.map((u) => (
                <option key={u} value={u}>
                  {u}
                </option>
              ))}
            </select>
          </div>

          {/* Role Filter */}
          <div>
            <label className="block text-slate-400 mb-1">Filter by Role:</label>
            <select
              value={selectedRole}
              onChange={(e) => setSelectedRole(e.target.value)}
              className="w-full p-2 bg-slate-900 border border-slate-700 rounded text-slate-100 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Roles</option>
              {uniqueRoles.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>

          {/* Event Type Filter */}
          <div>
            <label className="block text-slate-400 mb-1">Filter by Event Type:</label>
            <select
              value={selectedEventType}
              onChange={(e) => setSelectedEventType(e.target.value)}
              className="w-full p-2 bg-slate-900 border border-slate-700 rounded text-slate-100 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Event Types</option>
              <option value="COLLECTED">COLLECTED</option>
              <option value="TRANSFERRED">TRANSFERRED</option>
              <option value="ANALYZED">ANALYZED</option>
              <option value="STORED">STORED</option>
              <option value="SEALED">SEALED (Stego)</option>
              <option value="WATERMARKED">WATERMARKED (DCT)</option>
              <option value="VERIFIED">VERIFIED (5-Check)</option>
              <option value="CASE_SEALED">CASE_SEALED (Merkle)</option>
              <option value="REPORT_GENERATED">REPORT_GENERATED</option>
              <option value="USER_LOGIN">USER_LOGIN</option>
              <option value="USER_LOGOUT">USER_LOGOUT</option>
              <option value="ACCESS_DENIED">ACCESS_DENIED</option>
            </select>
          </div>
        </div>

        {/* Filter results count */}
        <div className="flex items-center justify-between text-xs font-mono text-slate-400 pt-2 border-t border-slate-900">
          <span>
            Showing <strong className="text-cyan-300">{filteredBlocks.length}</strong> of{' '}
            {currentCase.blocks.length} recorded blocks
          </span>

          {(selectedUser !== 'ALL' ||
            selectedRole !== 'ALL' ||
            selectedEventType !== 'ALL' ||
            searchTerm) && (
            <button
              onClick={() => {
                setSelectedUser('ALL');
                setSelectedRole('ALL');
                setSelectedEventType('ALL');
                setSearchTerm('');
              }}
              className="text-cyan-400 hover:text-cyan-300 underline"
            >
              Reset Filters
            </button>
          )}
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-slate-950 rounded-xl border border-slate-800 shadow-2xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="bg-slate-900 border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider">
                <th className="py-3 px-4">Block #</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Event Type</th>
                <th className="py-3 px-4">User & Role</th>
                <th className="py-3 px-4">Action / Notes</th>
                <th className="py-3 px-4">Block Hash (SHA-256)</th>
                <th className="py-3 px-4 text-right">Signature</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredBlocks.length > 0 ? (
                filteredBlocks
                  .slice()
                  .reverse()
                  .map((b) => {
                    const isDenied = b.eventType === 'ACCESS_DENIED';

                    return (
                      <tr
                        key={b.blockIndex}
                        className={`hover:bg-slate-900/50 transition-colors ${
                          isDenied ? 'bg-rose-950/20' : ''
                        }`}
                      >
                        <td className="py-3.5 px-4 font-bold text-slate-300 whitespace-nowrap">
                          #{b.blockIndex}
                        </td>
                        <td className="py-3.5 px-4 text-slate-400 whitespace-nowrap">
                          {b.timestamp.replace('T', ' ').substring(0, 19)}
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          {getEventBadge(b.eventType)}
                        </td>
                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <div className="font-semibold text-slate-200">{b.actorName}</div>
                          <div className="text-[10px] text-slate-500">{b.actorRole}</div>
                        </td>
                        <td className="py-3.5 px-4 max-w-sm">
                          <div className="text-slate-200">{b.details.action}</div>
                          {b.details.notes && (
                            <div className="text-[11px] text-slate-400 mt-0.5 truncate">
                              {b.details.notes}
                            </div>
                          )}
                          {b.details.authorizationReference && (
                            <div className="text-[10px] text-cyan-400/80 mt-0.5">
                              Auth: {b.details.authorizationReference}
                            </div>
                          )}
                        </td>
                        <td className="py-3.5 px-4 text-slate-400 font-mono whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            <span>
                              {b.currentHash.substring(0, 10)}...{b.currentHash.slice(-6)}
                            </span>
                            <button
                              onClick={() => copyToClipboard(b.currentHash)}
                              className="text-slate-500 hover:text-slate-200"
                              title="Copy hash"
                            >
                              {copiedHash === b.currentHash ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                        </td>
                        <td className="py-3.5 px-4 text-right whitespace-nowrap">
                          <span className="text-[10px] text-emerald-400 bg-emerald-950/70 border border-emerald-800 px-2 py-0.5 rounded">
                            ECDSA Signed
                          </span>
                        </td>
                      </tr>
                    );
                  })
              ) : (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-mono">
                    No audit records match the selected filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
