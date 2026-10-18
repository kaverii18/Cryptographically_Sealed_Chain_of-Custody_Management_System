/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useRef, useState } from 'react';
import {
  Shield,
  Lock,
  FileDown,
  FileUp,
  PlusCircle,
  CheckCircle2,
  AlertTriangle,
  Eye,
  Stamp,
  CheckCheck,
  FileText,
  Bot,
  GitCommit,
  Layers,
  HelpCircle,
  User,
  ChevronDown,
  LogOut,
  Sparkles,
  ClipboardList,
} from 'lucide-react';
import { ForensicCase, UserProfile } from '../types/forensics';
import { RbacPermissions } from '../services/rbacService';

export type AppTab =
  | 'dashboard'
  | 'ledger'
  | 'intake'
  | 'steganography'
  | 'watermarking'
  | 'verification'
  | 'merkle'
  | 'reports'
  | 'ai_assistant'
  | 'audit_log'
  | 'how_it_works'
  | 'officers';

interface NavbarProps {
  activeTab: AppTab;
  setActiveTab: (tab: AppTab) => void;
  currentCase: ForensicCase | null;
  currentUser: UserProfile;
  allUsers: UserProfile[];
  onSwitchUser: (user: UserProfile) => void;
  isChainValid: boolean | null;
  onExport: () => void;
  onImport: (file: File) => void;
  onNewIntake: () => void;
  onStartDemoMode: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  currentCase,
  currentUser,
  allUsers,
  onSwitchUser,
  isChainValid,
  onExport,
  onImport,
  onNewIntake,
  onStartDemoMode,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isUserMenuOpen, setIsUserMenuOpen] = useState<boolean>(false);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      onImport(file);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  };

  const getRoleBadge = (role: string) => {
    switch (role) {
      case 'COLLECTOR':
        return 'bg-amber-950/80 text-amber-300 border-amber-700/80';
      case 'ANALYST':
        return 'bg-cyan-950/80 text-cyan-300 border-cyan-700/80';
      case 'JUDGE':
        return 'bg-purple-950/80 text-purple-300 border-purple-700/80';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <header className="sticky top-0 z-40 bg-[#070b14]/95 backdrop-blur-md border-b border-slate-800/80 shadow-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-4">
          {/* Zone 1: Logo & System Identity */}
          <div className="flex items-center gap-3 shrink-0">
            <button
              onClick={() => setActiveTab('dashboard')}
              className="flex items-center gap-2.5 text-left group"
            >
              <div className="w-9 h-9 rounded-lg bg-cyan-950/70 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-sm shadow-cyan-950 group-hover:border-cyan-400 transition-colors">
                <Shield className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-base font-bold tracking-tight text-slate-100 font-mono whitespace-nowrap group-hover:text-cyan-300 transition-colors">
                    SealChain
                  </span>
                  <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 bg-cyan-950/70 border border-cyan-800/50 px-1.5 py-0.5 rounded hidden sm:inline">
                    P-256
                  </span>
                </div>
                <p className="text-[10px] text-slate-400 font-mono hidden md:block">
                  Forensic Custody Ledger
                </p>
              </div>
            </button>
          </div>

          {/* Zone 2: Navigation Links (Horizontal scroll on smaller screens) */}
          <nav className="flex items-center gap-1 overflow-x-auto no-scrollbar py-2 text-xs font-mono">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`px-2.5 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
                activeTab === 'dashboard'
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Dashboard</span>
            </button>

            <button
              onClick={() => setActiveTab('ledger')}
              className={`px-2.5 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
                activeTab === 'ledger'
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Ledger</span>
              {currentCase && (
                <span className="text-[10px] text-slate-400 ml-0.5">
                  ({currentCase.blocks.length})
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('intake')}
              className={`px-2.5 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
                activeTab === 'intake'
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>Intake</span>
            </button>

            <button
              onClick={() => setActiveTab('steganography')}
              className={`px-2.5 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
                activeTab === 'steganography'
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <Eye className="w-3.5 h-3.5" />
              <span>Stego</span>
            </button>

            <button
              onClick={() => setActiveTab('watermarking')}
              className={`px-2.5 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
                activeTab === 'watermarking'
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <Stamp className="w-3.5 h-3.5" />
              <span>Watermark</span>
            </button>

            <button
              onClick={() => setActiveTab('verification')}
              className={`px-2.5 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
                activeTab === 'verification'
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <CheckCheck className="w-3.5 h-3.5" />
              <span>Verify</span>
            </button>

            <button
              onClick={() => setActiveTab('merkle')}
              className={`px-2.5 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
                activeTab === 'merkle'
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <GitCommit className="w-3.5 h-3.5" />
              <span>Merkle Case</span>
            </button>

            <button
              onClick={() => setActiveTab('reports')}
              className={`px-2.5 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
                activeTab === 'reports'
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Reports</span>
            </button>

            <button
              onClick={() => setActiveTab('ai_assistant')}
              className={`px-2.5 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
                activeTab === 'ai_assistant'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <Bot className="w-3.5 h-3.5 text-cyan-400" />
              <span>AI Assistant</span>
            </button>

            <button
              onClick={() => setActiveTab('audit_log')}
              className={`px-2.5 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
                activeTab === 'audit_log'
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <ClipboardList className="w-3.5 h-3.5" />
              <span>Audit Log</span>
            </button>

            <button
              onClick={() => setActiveTab('how_it_works')}
              className={`px-2.5 py-1.5 rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
                activeTab === 'how_it_works'
                  ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
              }`}
            >
              <HelpCircle className="w-3.5 h-3.5" />
              <span>Architecture</span>
            </button>
          </nav>

          {/* Zone 3: Role Switcher & Action Tools */}
          <div className="flex items-center gap-2 shrink-0">
            {/* RBAC Active Role Selector Dropdown */}
            <div className="relative">
              <button
                onClick={() => setIsUserMenuOpen(!isUserMenuOpen)}
                className={`px-2.5 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer ${getRoleBadge(
                  currentUser.role
                )}`}
                title="Switch active role / user"
              >
                <User className="w-3 h-3" />
                <span className="font-bold">{currentUser.role}</span>
                <ChevronDown className="w-3 h-3 opacity-60" />
              </button>

              {isUserMenuOpen && (
                <div className="absolute right-0 mt-2 w-64 rounded-xl bg-slate-900 border border-slate-800 shadow-2xl p-2 z-50 text-xs font-mono space-y-1">
                  <div className="px-2 py-1.5 text-[10px] text-slate-400 uppercase tracking-wider border-b border-slate-800">
                    Switch Forensic Identity (RBAC):
                  </div>

                  {allUsers.map((u) => {
                    const isSelected = u.id === currentUser.id;
                    return (
                      <button
                        key={u.id}
                        onClick={() => {
                          onSwitchUser(u);
                          setIsUserMenuOpen(false);
                        }}
                        className={`w-full p-2 rounded-lg text-left transition-colors flex flex-col gap-0.5 cursor-pointer ${
                          isSelected
                            ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                            : 'hover:bg-slate-800/60 text-slate-300'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold">{u.name}</span>
                          <span className={`text-[9px] px-1.5 py-0.2 rounded border ${getRoleBadge(u.role)}`}>
                            {u.role}
                          </span>
                        </div>
                        <span className="text-[10px] text-slate-400 truncate">{u.title}</span>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Hidden File Input for Ledger JSON Import */}
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileChange}
              accept=".json"
              className="hidden"
            />

            <button
              onClick={() => fileInputRef.current?.click()}
              title="Import JSON Ledger"
              className="p-1.5 text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 rounded-md transition-colors"
            >
              <FileUp className="w-4 h-4" />
            </button>

            <button
              onClick={onExport}
              title="Export Ledger as JSON"
              className="p-1.5 text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 rounded-md transition-colors"
            >
              <FileDown className="w-4 h-4" />
            </button>

            <button
              onClick={onStartDemoMode}
              title="Launch 3-minute presentation tour"
              className="px-2.5 py-1.5 rounded-md bg-gradient-to-r from-cyan-500 to-teal-400 text-slate-950 text-xs font-mono font-bold flex items-center gap-1 shadow-sm transition-all"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Demo Tour</span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
