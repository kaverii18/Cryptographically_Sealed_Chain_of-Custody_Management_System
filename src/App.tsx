/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  RefreshCw,
  CheckCircle,
  AlertOctagon,
  FileText,
  Lock,
  Cpu,
} from 'lucide-react';
import {
  ForensicCase,
  ActorIdentity,
  CustodyBlock,
  ChainVerificationReport,
  UserProfile,
  ComprehensiveVerificationReport,
} from './types/forensics';
import {
  loadOrCreateCase,
  saveActiveCase,
  exportCaseToJson,
  importCaseFromJson,
  applyTamperToBlock,
  restoreBackupCase,
} from './services/storageService';
import { verifyChainIntegrity, createSignedBlock } from './crypto/webCrypto';
import {
  initializeRbacUsers,
  getActiveUserId,
  setActiveUserId,
  RbacPermissions,
} from './services/rbacService';

import { Navbar, AppTab } from './components/Navbar';
import { DashboardView } from './components/DashboardView';
import { CustodyLedger } from './components/CustodyLedger';
import { EvidenceIntake } from './components/EvidenceIntake';
import { SteganographyModule } from './components/SteganographyModule';
import { WatermarkingModule } from './components/WatermarkingModule';
import { ForensicVerificationModule } from './components/ForensicVerificationModule';
import { MerkleCaseSealModule } from './components/MerkleCaseSealModule';
import { ReportsModule } from './components/ReportsModule';
import { AiAssistantModule } from './components/AiAssistantModule';
import { AuditLogView } from './components/AuditLogView';
import { HowItWorksView } from './components/HowItWorksView';
import { ActorKeyManager } from './components/ActorKeyManager';
import { TamperModal } from './components/TamperModal';
import { AddEventModal } from './components/AddEventModal';
import { BlockDetailModal } from './components/BlockDetailModal';
import { DemoTourBar, DEMO_STEPS } from './components/DemoTourBar';

export default function App() {
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [currentCase, setCurrentCase] = useState<ForensicCase | null>(null);
  const [actors, setActors] = useState<ActorIdentity[]>([]);
  const [rbacUsers, setRbacUsers] = useState<UserProfile[]>([]);
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(null);

  // Navigation state (defaults to Dashboard)
  const [activeTab, setActiveTab] = useState<AppTab>('dashboard');

  // Forensic Verification State
  const [verificationReport, setVerificationReport] = useState<ChainVerificationReport | null>(null);
  const [comprehensiveReport, setComprehensiveReport] = useState<ComprehensiveVerificationReport | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);

  // AI Forensic Brief saved for PDF inclusion
  const [savedAiExplanation, setSavedAiExplanation] = useState<string | null>(null);

  // Guided Presentation Demo Mode
  const [isDemoTourOpen, setIsDemoTourOpen] = useState<boolean>(false);
  const [demoStepIndex, setDemoStepIndex] = useState<number>(0);

  // Modals
  const [isTamperModalOpen, setIsTamperModalOpen] = useState<boolean>(false);
  const [isAddEventModalOpen, setIsAddEventModalOpen] = useState<boolean>(false);
  const [inspectedBlock, setInspectedBlock] = useState<CustodyBlock | null>(null);

  // System Notification Toast
  const [notification, setNotification] = useState<{
    type: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const showNotification = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
    setNotification({ type, message });
    setTimeout(() => {
      setNotification(null);
    }, 4500);
  };

  // Run chain verification using Web Crypto API
  const handleVerifyChain = useCallback(async (blocksToVerify?: CustodyBlock[]) => {
    const blocks = blocksToVerify || currentCase?.blocks;
    if (!blocks || blocks.length === 0) return;

    setIsVerifying(true);
    try {
      const report = await verifyChainIntegrity(blocks);
      setVerificationReport(report);

      if (report.isChainValid) {
        showNotification(
          `Chain Integrity Confirmed: All ${report.totalBlocks} blocks are cryptographically valid.`,
          'success'
        );
      } else {
        showNotification(
          `INTEGRITY BREACH: Chain compromised at Block #${report.firstBrokenBlockIndex}. Broken link detected.`,
          'error'
        );
      }
    } catch (err: unknown) {
      console.error('Verification error:', err);
      const msg = err instanceof Error ? err.message : 'Cryptographic verification error';
      showNotification(`Verification failure: ${msg}`, 'error');
    } finally {
      setIsVerifying(false);
    }
  }, [currentCase?.blocks]);

  // Initial Load from localStorage or seed demo
  useEffect(() => {
    async function init() {
      setIsLoading(true);
      try {
        // 1. Initialize RBAC Users with Web Crypto ECDSA keypairs
        const users = await initializeRbacUsers();
        setRbacUsers(users);

        const activeId = getActiveUserId();
        const activeUser = users.find((u) => u.id === activeId) || users[1] || users[0];
        setCurrentUser(activeUser);

        // 2. Load or create default Forensic Case
        const { caseData, actors: loadedActors } = await loadOrCreateCase();
        setCurrentCase(caseData);
        setActors(loadedActors);

        // 3. Initial chain verification check
        const initialReport = await verifyChainIntegrity(caseData.blocks);
        setVerificationReport(initialReport);
      } catch (err) {
        console.error('Initialization error:', err);
        showNotification('Failed to initialize custody ledger.', 'error');
      } finally {
        setIsLoading(false);
      }
    }

    init();
  }, []);

  // Handle Switch User (Role-Based Access Control)
  const handleSwitchUser = async (newUser: UserProfile) => {
    if (!currentCase || !currentUser || newUser.id === currentUser.id) {
      setCurrentUser(newUser);
      setActiveUserId(newUser.id);
      return;
    }

    const previousUser = currentUser;
    setCurrentUser(newUser);
    setActiveUserId(newUser.id);

    // Log USER_LOGOUT and USER_LOGIN audit events to custody ledger
    try {
      const headBlock = currentCase.blocks[currentCase.blocks.length - 1];
      const prevHash = headBlock ? headBlock.currentHash : '0000000000000000000000000000000000000000000000000000000000000000';
      const nextIndex = currentCase.blocks.length;

      const loginBlock = await createSignedBlock({
        blockIndex: nextIndex,
        previousHash: prevHash,
        eventType: 'USER_LOGIN',
        actor: {
          id: newUser.id,
          name: newUser.name,
          role: newUser.role,
          agency: newUser.agency,
          badgeNumber: newUser.badge,
          publicKeyJwk: newUser.publicKeyJwk,
          privateKeyJwk: newUser.privateKeyJwk,
        },
        details: {
          action: `User Session Switch: Authenticated as [${newUser.name}] (${newUser.role})`,
          departmentOrAgency: newUser.agency,
          facilityLocation: 'Digital Forensics Terminal — Station #01',
          toolOrMethodUsed: 'SealChain Web Crypto Identity Gate (ECDSA P-256 Session Token)',
          notes: `Switched from previous session [${previousUser.name}]. Role permissions updated to ${newUser.role}.`,
          authorizationReference: `Session Token #${newUser.badge}-${Date.now().toString().slice(-6)}`,
        },
        evidenceId: currentCase.evidence.evidenceId,
        evidenceHash: currentCase.evidence.sha256Hash,
      });

      const updatedBlocks = [...currentCase.blocks, loginBlock];
      const updatedCase = { ...currentCase, blocks: updatedBlocks };
      setCurrentCase(updatedCase);
      saveActiveCase(updatedCase);

      showNotification(
        `Session switched to ${newUser.name} (${newUser.role}). Logged to ledger as Block #${nextIndex}.`,
        'info'
      );
    } catch (err) {
      console.error('Failed to log session block:', err);
    }
  };

  // Handle Tamper Demo Action
  const handleApplyTamper = async (
    blockIndex: number,
    tamperType: 'ACTOR' | 'TIMESTAMP' | 'NOTES' | 'EVIDENCE_HASH' | 'CURRENT_HASH' | 'PREVIOUS_HASH',
    customValue?: string
  ) => {
    if (!currentCase) return;

    if (currentUser && !RbacPermissions.canTamperDemo(currentUser.role).allowed) {
      showNotification(
        `Permission Denied: Only certified Forensic Analysts can execute tampering simulation attacks.`,
        'error'
      );
      return;
    }

    const tampered = applyTamperToBlock(currentCase, blockIndex, tamperType, customValue);
    setCurrentCase(tampered);

    showNotification(
      `Tampering injected into Block #${blockIndex} (${tamperType}). Re-verifying chain...`,
      'info'
    );

    // Re-verify immediately to show the "BROKEN LINK" state in action!
    await handleVerifyChain(tampered.blocks);
  };

  // Restore untampered state
  const handleRestoreBackup = async () => {
    const restored = restoreBackupCase();
    if (restored) {
      setCurrentCase(restored);
      showNotification('Restored original uncompromised chain of custody state.', 'success');
      await handleVerifyChain(restored.blocks);
    } else {
      showNotification('No valid backup state found in storage.', 'error');
    }
  };

  // Add new custody event
  const handleEventAdded = async (newBlock: CustodyBlock) => {
    if (!currentCase) return;

    const updatedBlocks = [...currentCase.blocks, newBlock];
    const updatedCase: ForensicCase = {
      ...currentCase,
      blocks: updatedBlocks,
    };

    saveActiveCase(updatedCase);
    setCurrentCase(updatedCase);
    showNotification(
      `Block #${newBlock.blockIndex} [${newBlock.eventType}] successfully sealed and appended to chain.`,
      'success'
    );

    // Verify updated chain
    await handleVerifyChain(updatedBlocks);
  };

  // Update case (e.g. from Merkle sealing or specimen changes)
  const handleUpdateCase = (updatedCase: ForensicCase) => {
    setCurrentCase(updatedCase);
    saveActiveCase(updatedCase);
  };

  // Export JSON
  const handleExport = () => {
    if (!currentCase) return;
    exportCaseToJson(currentCase);
    showNotification(`Exported ledger for Case ${currentCase.caseId} as JSON.`, 'success');
  };

  // Import JSON
  const handleImport = async (file: File) => {
    try {
      const text = await file.text();
      const imported = importCaseFromJson(text);
      setCurrentCase(imported);
      setActiveTab('ledger');
      showNotification(`Imported Case ${imported.caseId} (${imported.blocks.length} blocks).`, 'success');

      // Verify newly imported chain
      await handleVerifyChain(imported.blocks);
    } catch (err: unknown) {
      console.error('Import error:', err);
      const msg = err instanceof Error ? err.message : 'Invalid JSON file';
      showNotification(`Import failed: ${msg}`, 'error');
    }
  };

  // New Evidence Intake Case created
  const handleCaseCreated = async (newCase: ForensicCase) => {
    setCurrentCase(newCase);
    setActiveTab('ledger');
    showNotification(
      `New Case ${newCase.caseId} initiated. Genesis Block #0 sealed and signed.`,
      'success'
    );
    await handleVerifyChain(newCase.blocks);
  };

  // Demo Tour Step Change
  const handleSelectDemoStep = (stepIdx: number) => {
    setDemoStepIndex(stepIdx);
    const step = DEMO_STEPS[stepIdx];
    if (step) {
      setActiveTab(step.tab);
    }
  };

  if (isLoading || !currentUser) {
    return (
      <div className="min-h-screen bg-[#070b14] flex flex-col items-center justify-center text-slate-300 font-mono">
        <div className="w-12 h-12 rounded-xl bg-cyan-950/60 border border-cyan-500/40 flex items-center justify-center text-cyan-400 mb-4 animate-pulse">
          <Shield className="w-6 h-6" />
        </div>
        <div className="flex items-center gap-2 text-sm text-cyan-400">
          <RefreshCw className="w-4 h-4 animate-spin" />
          <span>Initializing Web Crypto Environment & Seeding Forensic Ledger...</span>
        </div>
        <p className="text-xs text-slate-500 mt-2">
          Generating ECDSA P-256 Keypairs & Computing FIPS 180-4 SHA-256 Hashes
        </p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-200 selection:bg-cyan-500/30 selection:text-cyan-200 flex flex-col">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        currentCase={currentCase}
        currentUser={currentUser}
        allUsers={rbacUsers}
        onSwitchUser={handleSwitchUser}
        isChainValid={verificationReport ? verificationReport.isChainValid : null}
        onExport={handleExport}
        onImport={handleImport}
        onNewIntake={() => setActiveTab('intake')}
        onStartDemoMode={() => {
          setIsDemoTourOpen(true);
          handleSelectDemoStep(0);
        }}
      />

      {/* Floating System Notification Toast */}
      {notification && (
        <div className="fixed bottom-6 right-6 z-50 max-w-md animate-in fade-in slide-in-from-bottom-4 duration-200">
          <div
            className={`p-4 rounded-xl border shadow-2xl flex items-start gap-3 backdrop-blur-md ${
              notification.type === 'error'
                ? 'bg-rose-950/90 border-rose-600 text-rose-200'
                : notification.type === 'success'
                ? 'bg-emerald-950/90 border-emerald-600 text-emerald-200'
                : 'bg-slate-900/90 border-slate-700 text-slate-200'
            }`}
          >
            {notification.type === 'error' ? (
              <AlertOctagon className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            ) : notification.type === 'success' ? (
              <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <Shield className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
            )}
            <div className="text-xs font-mono leading-relaxed">
              {notification.message}
            </div>
          </div>
        </div>
      )}

      {/* Main Content Area */}
      <main className="flex-1 pb-20">
        {activeTab === 'dashboard' && currentCase && (
          <DashboardView
            currentCase={currentCase}
            currentUser={currentUser}
            isChainValid={verificationReport ? verificationReport.isChainValid : null}
            verificationReport={comprehensiveReport}
            onNavigate={(tab) => setActiveTab(tab)}
            onStartDemoMode={() => {
              setIsDemoTourOpen(true);
              handleSelectDemoStep(0);
            }}
            onVerifyChain={() => handleVerifyChain()}
          />
        )}

        {activeTab === 'ledger' && currentCase && (
          <CustodyLedger
            currentCase={currentCase}
            verificationReport={verificationReport}
            isVerifying={isVerifying}
            onVerifyChain={() => handleVerifyChain()}
            onOpenTamperModal={() => setIsTamperModalOpen(true)}
            onOpenAddEventModal={() => setIsAddEventModalOpen(true)}
            onRestoreBackup={handleRestoreBackup}
            onOpenBlockDetail={(block) => setInspectedBlock(block)}
            hasBackup={true}
          />
        )}

        {activeTab === 'intake' && (
          <EvidenceIntake
            actors={actors}
            onCaseCreated={handleCaseCreated}
            onCancel={currentCase ? () => setActiveTab('ledger') : undefined}
          />
        )}

        {activeTab === 'steganography' && currentCase && (
          <SteganographyModule
            currentCase={currentCase}
            actors={actors}
            onAddCustodyBlock={handleEventAdded}
            onNavigateToLedger={() => setActiveTab('ledger')}
          />
        )}

        {activeTab === 'watermarking' && currentCase && (
          <WatermarkingModule
            currentCase={currentCase}
            actors={actors}
            onAddCustodyBlock={handleEventAdded}
            onNavigateToLedger={() => setActiveTab('ledger')}
          />
        )}

        {activeTab === 'verification' && currentCase && (
          <ForensicVerificationModule
            currentCase={currentCase}
            actors={actors}
            onAddCustodyBlock={handleEventAdded}
            onNavigateToLedger={() => setActiveTab('ledger')}
            onNavigateToReports={() => setActiveTab('reports')}
            onVerificationComplete={(report) => setComprehensiveReport(report)}
          />
        )}

        {activeTab === 'merkle' && currentCase && (
          <MerkleCaseSealModule
            currentCase={currentCase}
            currentUser={currentUser}
            onUpdateCase={handleUpdateCase}
            onAddCustodyBlock={handleEventAdded}
            onNavigateToLedger={() => setActiveTab('ledger')}
            onNavigateToReports={() => setActiveTab('reports')}
          />
        )}

        {activeTab === 'reports' && currentCase && (
          <ReportsModule
            currentCase={currentCase}
            actors={actors}
            activeVerificationReport={comprehensiveReport}
            aiExplanationText={savedAiExplanation}
            onAddCustodyBlock={handleEventAdded}
            onNavigateToVerification={() => setActiveTab('verification')}
            onNavigateToLedger={() => setActiveTab('ledger')}
          />
        )}

        {activeTab === 'ai_assistant' && currentCase && (
          <AiAssistantModule
            currentCase={currentCase}
            currentUser={currentUser}
            verificationReport={comprehensiveReport}
            onNavigateToVerification={() => setActiveTab('verification')}
            onNavigateToReports={() => setActiveTab('reports')}
            onSaveAiExplanationForReport={(text) => {
              setSavedAiExplanation(text);
              showNotification('AI Forensic Brief attached to official PDF report.', 'success');
            }}
            savedAiExplanation={savedAiExplanation}
          />
        )}

        {activeTab === 'audit_log' && currentCase && (
          <AuditLogView currentCase={currentCase} />
        )}

        {activeTab === 'how_it_works' && <HowItWorksView />}

        {activeTab === 'officers' && (
          <ActorKeyManager
            actors={actors}
            onActorsUpdated={(updated) => setActors(updated)}
          />
        )}
      </main>

      {/* Guided 3-Minute Demo Tour Bar */}
      {isDemoTourOpen && (
        <DemoTourBar
          currentStepIndex={demoStepIndex}
          onSelectStep={handleSelectDemoStep}
          onClose={() => setIsDemoTourOpen(false)}
        />
      )}

      {/* Footer / Lab Specifications */}
      <footer className="mt-auto border-t border-slate-800/80 bg-slate-950/70 py-6 text-xs text-slate-400">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-mono text-slate-300 font-semibold">SealChain</span>
            <span aria-hidden="true">·</span>
            <span>Cryptographically Sealed Digital Forensic Custody & Audit System</span>
          </div>

          <div className="flex flex-wrap items-center gap-4 font-mono text-[11px] text-slate-400">
            <span className="flex items-center gap-1">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span>NIST SHA-256</span>
            </span>
            <span aria-hidden="true">·</span>
            <span className="flex items-center gap-1">
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
              <span>ECDSA P-256</span>
            </span>
            <span aria-hidden="true">·</span>
            <span className="flex items-center gap-1">
              <FileText className="w-3.5 h-3.5 text-amber-400" />
              <span>RFC 6962 Merkle Trees</span>
            </span>
          </div>
        </div>
      </footer>

      {/* Modals */}
      {currentCase && (
        <>
          <TamperModal
            isOpen={isTamperModalOpen}
            onClose={() => setIsTamperModalOpen(false)}
            currentCase={currentCase}
            onApplyTamper={handleApplyTamper}
          />

          <AddEventModal
            isOpen={isAddEventModalOpen}
            onClose={() => setIsAddEventModalOpen(false)}
            currentCase={currentCase}
            actors={actors}
            onEventAdded={handleEventAdded}
          />
        </>
      )}

      <BlockDetailModal
        block={inspectedBlock}
        onClose={() => setInspectedBlock(null)}
      />
    </div>
  );
}
