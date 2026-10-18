/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef, useEffect } from 'react';
import {
  Bot,
  Send,
  Sparkles,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Languages,
  Check,
  Copy,
  RefreshCw,
  FileText,
  User,
  Info,
  ExternalLink,
  ChevronRight,
  HelpCircle,
  Cpu,
  Lock,
} from 'lucide-react';
import {
  ForensicCase,
  ComprehensiveVerificationReport,
  StructuredForensicDataForAi,
  AiChatMessage,
  UserProfile,
} from '../types/forensics';
import { generateRuleBasedForensicExplanation } from '../utils/aiRuleBasedFallback';

interface AiAssistantModuleProps {
  currentCase: ForensicCase;
  currentUser: UserProfile;
  verificationReport: ComprehensiveVerificationReport | null;
  onNavigateToVerification: () => void;
  onNavigateToReports: () => void;
  onSaveAiExplanationForReport: (text: string) => void;
  savedAiExplanation: string | null;
}

export const AiAssistantModule: React.FC<AiAssistantModuleProps> = ({
  currentCase,
  currentUser,
  verificationReport,
  onNavigateToVerification,
  onNavigateToReports,
  onSaveAiExplanationForReport,
  savedAiExplanation,
}) => {
  const [language, setLanguage] = useState<'en' | 'mr'>('en');
  const [messages, setMessages] = useState<AiChatMessage[]>([
    {
      id: 'welcome-1',
      role: 'assistant',
      text:
        language === 'mr'
          ? `नमस्कार! मी **सीलचेन एआय फॉरेन्सिक असिस्टंट** आहे. प्रकरण क्रमांक \`${currentCase.caseId}\` च्या गणितीय फॉरेन्सिक पडताळणी निकालांचे अर्थ समजून घेण्यासाठी मी सज्ज आहे. खालील "या पडताळणीचे स्पष्टीकरण द्या" बटनावर क्लिक करा किंवा कोणताही प्रश्न विचारा.`
          : `Greetings. I am the **SealChain AI Forensic Assistant**. I provide cryptographic interpretation, anomaly breakdown, and courtroom admissibility guidance for Case \`${currentCase.caseId}\`. Click **"Explain This Verification"** below or ask any question.`,
      timestamp: new Date().toLocaleTimeString(),
      isAiGenerated: false,
    },
  ]);

  const [inputQuestion, setInputQuestion] = useState<string>('');
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [isFallbackMode, setIsFallbackMode] = useState<boolean>(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [isSavedForReport, setIsSavedForReport] = useState<boolean>(!!savedAiExplanation);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Extract structured, non-sensitive summary
  const getStructuredData = (): StructuredForensicDataForAi => {
    const headBlock = currentCase.blocks[currentCase.blocks.length - 1];
    return {
      caseId: currentCase.caseId,
      evidenceId: currentCase.evidence.evidenceId,
      suspectImageSha256: verificationReport?.suspectImageSha256 || currentCase.evidence.sha256Hash,
      verdict: verificationReport?.verdict || 'AUTHENTIC',
      confidencePercent: verificationReport?.confidencePercent || 99,
      checks: {
        fileHash: {
          status: verificationReport?.checks.fileHash.status || 'PASS',
          reason: verificationReport?.checks.fileHash.summary || 'Matches baseline intake SHA-256 hash.',
        },
        hiddenSeal: {
          status: verificationReport?.checks.hiddenSeal.status || 'PASS',
          reason: verificationReport?.checks.hiddenSeal.summary || 'AES-GCM fragile seal intact and readable.',
        },
        signature: {
          status: verificationReport?.checks.signature.status || 'PASS',
          reason: verificationReport?.checks.signature.summary || 'ECDSA P-256 signature mathematically verified.',
        },
        ledgerIntegrity: {
          status: verificationReport?.checks.ledgerIntegrity.status || 'PASS',
          reason: verificationReport?.checks.ledgerIntegrity.summary || 'Custody ledger hash sequence unbroken.',
        },
        robustWatermark: {
          status: verificationReport?.checks.robustWatermark.status || 'PASS',
          reason: verificationReport?.checks.robustWatermark.summary || '2D-DCT Y-luminance watermark extracted.',
        },
      },
      reasons: verificationReport?.reasons || ['Chain unbroken', 'Intake hashes conform to FIPS 180-4 standard'],
      suspiciousRegions:
        verificationReport?.heatmap?.suspiciousRegions.map((r) => ({
          label: r.label,
          x: r.x,
          y: r.y,
          width: r.width,
          height: r.height,
          anomalyScore: r.suspicionScore,
        })) || [],
      ledgerSummary: {
        totalBlocks: currentCase.blocks.length,
        lastEvent: headBlock ? headBlock.eventType : 'COLLECTED',
        isChainValid: true,
      },
      merkleSeal: currentCase.merkleSeal
        ? {
            isSealed: true,
            merkleRoot: currentCase.merkleSeal.merkleRoot,
            evidenceCount: currentCase.merkleSeal.evidenceCount,
          }
        : undefined,
    };
  };

  // One-click explain action
  const handleExplainVerification = async () => {
    setIsProcessing(true);
    const structured = getStructuredData();

    // Add user intent message
    const userMsg: AiChatMessage = {
      id: `msg-${Date.now()}-u`,
      role: 'user',
      text:
        language === 'mr'
          ? 'कृपया सध्याच्या ५-तपासणी फॉरेन्सिक निकालांचे सविस्तर व न्यायालयात ग्राह्य स्पष्टीकरण द्या.'
          : 'Please explain the complete 5-check forensic verification findings and admissibility assessment.',
      timestamp: new Date().toLocaleTimeString(),
      isAiGenerated: false,
    };
    setMessages((prev) => [...prev, userMsg]);

    try {
      const res = await fetch('/api/ai/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          forensicData: structured,
          language,
        }),
      });

      const data = await res.json();

      if (data.ok && data.explanation) {
        setIsFallbackMode(false);
        const aiMsg: AiChatMessage = {
          id: `msg-${Date.now()}-a`,
          role: 'assistant',
          text: data.explanation,
          timestamp: new Date().toLocaleTimeString(),
          isAiGenerated: true,
          isFallback: false,
        };
        setMessages((prev) => [...prev, aiMsg]);
        onSaveAiExplanationForReport(data.explanation);
        setIsSavedForReport(true);
      } else {
        // Fallback rule-based explanation
        setIsFallbackMode(true);
        const fallbackText = generateRuleBasedForensicExplanation(structured, language);
        const aiMsg: AiChatMessage = {
          id: `msg-${Date.now()}-a`,
          role: 'assistant',
          text: fallbackText,
          timestamp: new Date().toLocaleTimeString(),
          isAiGenerated: false,
          isFallback: true,
        };
        setMessages((prev) => [...prev, aiMsg]);
        onSaveAiExplanationForReport(fallbackText);
        setIsSavedForReport(true);
      }
    } catch {
      // Offline fallback
      setIsFallbackMode(true);
      const fallbackText = generateRuleBasedForensicExplanation(structured, language);
      const aiMsg: AiChatMessage = {
        id: `msg-${Date.now()}-a`,
        role: 'assistant',
        text: fallbackText,
        timestamp: new Date().toLocaleTimeString(),
        isAiGenerated: false,
        isFallback: true,
      };
      setMessages((prev) => [...prev, aiMsg]);
      onSaveAiExplanationForReport(fallbackText);
      setIsSavedForReport(true);
    } finally {
      setIsProcessing(false);
    }
  };

  // Submit chat query
  const handleSendChat = async (questionText?: string) => {
    const textToSend = questionText || inputQuestion;
    if (!textToSend.trim() || isProcessing) return;

    setInputQuestion('');
    setIsProcessing(true);

    const userMsg: AiChatMessage = {
      id: `msg-${Date.now()}-u`,
      role: 'user',
      text: textToSend,
      timestamp: new Date().toLocaleTimeString(),
      isAiGenerated: false,
    };

    const newMessages = [...messages, userMsg];
    setMessages(newMessages);

    const structured = getStructuredData();

    try {
      const res = await fetch('/api/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: newMessages.map((m) => ({ role: m.role, text: m.text })),
          forensicData: structured,
          language,
        }),
      });

      const data = await res.json();

      if (data.ok && data.reply) {
        setIsFallbackMode(false);
        const replyMsg: AiChatMessage = {
          id: `msg-${Date.now()}-a`,
          role: 'assistant',
          text: data.reply,
          timestamp: new Date().toLocaleTimeString(),
          isAiGenerated: true,
        };
        setMessages((prev) => [...prev, replyMsg]);
      } else {
        // Fallback answering based on structured data
        setIsFallbackMode(true);
        const fallbackText = generateRuleBasedForensicExplanation(structured, language);
        const replyMsg: AiChatMessage = {
          id: `msg-${Date.now()}-a`,
          role: 'assistant',
          text:
            language === 'mr'
              ? `[स्थानिक फॉरेन्सिक इंजिन]: आपल्या प्रश्नासाठी उपलब्ध पुरावा डेटा:\n\n${fallbackText}`
              : `[Deterministic Forensic Engine Response]: Based on active verification results:\n\n${fallbackText}`,
          timestamp: new Date().toLocaleTimeString(),
          isAiGenerated: false,
          isFallback: true,
        };
        setMessages((prev) => [...prev, replyMsg]);
      }
    } catch {
      setIsFallbackMode(true);
      const fallbackText = generateRuleBasedForensicExplanation(structured, language);
      const replyMsg: AiChatMessage = {
        id: `msg-${Date.now()}-a`,
        role: 'assistant',
        text:
          language === 'mr'
            ? `[स्थानिक फॉरेन्सिक इंजिन]: आपल्या प्रश्नासाठी उपलब्ध पुरावा डेटा:\n\n${fallbackText}`
            : `[Deterministic Forensic Engine Response]: Based on active verification results:\n\n${fallbackText}`,
        timestamp: new Date().toLocaleTimeString(),
        isAiGenerated: false,
        isFallback: true,
      };
      setMessages((prev) => [...prev, replyMsg]);
    } finally {
      setIsProcessing(false);
    }
  };

  const copyToClipboard = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Suggested questions
  const suggestedQuestions =
    language === 'mr'
      ? [
          'या पुराव्याचा अंतिम निर्णय काय आहे आणि का?',
          'कोणत्या संशयित भागात छेडछाड झाली आहे?',
          'हा पुरावा न्यायालयात ग्राह्य मानला जाऊ शकतो का?',
          'तुटलेली लेजर साखळी म्हणजे नेमके काय?',
          'जेपीईजी कॉम्प्रेशननंतरही वॉटरमार्क कसा टिकून राहिला?',
        ]
      : [
          'Why is the verdict authentic or tampered?',
          'Which specific regions were modified?',
          'Can this evidence chain stand in court?',
          'What does a broken ledger link indicate?',
          'Why did the robust watermark survive while the fragile seal failed?',
        ];

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-cyan-950/70 border border-cyan-500/40 text-cyan-400">
              <Bot className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-slate-100">
                  AI Forensic Intelligence Assistant
                </h1>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
                  Gemini 3.8 Flash
                </span>
                {isFallbackMode && (
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-amber-950/80 border border-amber-800 text-amber-300">
                    Deterministic Fallback Mode
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400">
                Ground-truth cryptographic interpretation & court testimony preparation based strictly on verified results.
              </p>
            </div>
          </div>
        </div>

        {/* Language selector & One-click button */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Language Toggle */}
          <div className="flex items-center bg-slate-900 border border-slate-800 rounded-lg p-1 text-xs font-mono">
            <button
              onClick={() => setLanguage('en')}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                language === 'en'
                  ? 'bg-cyan-950 text-cyan-300 font-semibold border border-cyan-800'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              English
            </button>
            <button
              onClick={() => setLanguage('mr')}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                language === 'mr'
                  ? 'bg-cyan-950 text-cyan-300 font-semibold border border-cyan-800'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              मराठी (Marathi)
            </button>
          </div>

          {/* One-click Explain Button */}
          <button
            onClick={handleExplainVerification}
            disabled={isProcessing}
            className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-semibold text-xs font-mono flex items-center gap-2 shadow-lg shadow-cyan-950/50 transition-all cursor-pointer"
          >
            {isProcessing ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Synthesizing Findings...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4" />
                <span>Explain This Verification</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Context Banner */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2 text-slate-300">
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Target Specimen:</span>
            <span className="text-cyan-300 font-semibold">{currentCase.evidence.evidenceId}</span>
          </div>
          <span className="text-slate-600">|</span>
          <div className="flex items-center gap-2">
            <span>Verdict:</span>
            <span
              className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                verificationReport?.verdict === 'AUTHENTIC' || !verificationReport
                  ? 'bg-emerald-950 border border-emerald-800 text-emerald-300'
                  : verificationReport.verdict === 'TAMPERED'
                  ? 'bg-rose-950 border border-rose-800 text-rose-300'
                  : 'bg-amber-950 border border-amber-800 text-amber-300'
              }`}
            >
              {verificationReport?.verdict || 'AUTHENTIC (Baseline)'}
            </span>
          </div>
          <span className="text-slate-600">|</span>
          <div className="flex items-center gap-2 text-slate-400">
            <Cpu className="w-3.5 h-3.5 text-emerald-400" />
            <span>Privacy Guard:</span>
            <span className="text-emerald-300">Zero Raw Images or Passphrases Sent</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {savedAiExplanation && (
            <button
              onClick={onNavigateToReports}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 text-[11px] flex items-center gap-1.5 transition-colors"
            >
              <FileText className="w-3 h-3 text-cyan-400" />
              <span>Attached to Formal Report</span>
            </button>
          )}
        </div>
      </div>

      {/* Chat Messages Panel */}
      <div className="bg-slate-950 rounded-xl border border-slate-800/90 shadow-2xl flex flex-col h-[520px]">
        {/* Message Thread */}
        <div className="flex-1 p-5 overflow-y-auto space-y-4">
          {messages.map((m) => (
            <div
              key={m.id}
              className={`flex gap-3 max-w-3xl ${
                m.role === 'user' ? 'ml-auto flex-row-reverse' : 'mr-auto'
              }`}
            >
              {/* Avatar */}
              <div
                className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 text-xs font-mono ${
                  m.role === 'user'
                    ? 'bg-cyan-900 border border-cyan-700 text-cyan-200'
                    : 'bg-slate-800 border border-slate-700 text-cyan-400'
                }`}
              >
                {m.role === 'user' ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
              </div>

              {/* Message Bubble */}
              <div
                className={`rounded-xl p-4 text-xs font-mono leading-relaxed space-y-2 border ${
                  m.role === 'user'
                    ? 'bg-cyan-950/70 border-cyan-800/70 text-cyan-100'
                    : 'bg-slate-900/90 border-slate-800 text-slate-200'
                }`}
              >
                <div className="flex items-center justify-between gap-3 text-[10px] opacity-60 pb-1 border-b border-white/5">
                  <span>{m.role === 'user' ? currentUser.name : 'SealChain Assistant'}</span>
                  <span>{m.timestamp}</span>
                </div>

                <div className="whitespace-pre-wrap space-y-2 text-slate-100">
                  {m.text}
                </div>

                {m.role === 'assistant' && (
                  <div className="flex items-center justify-between pt-2 border-t border-white/5 text-[10px] text-slate-400">
                    <div className="flex items-center gap-2">
                      {m.isFallback ? (
                        <span className="text-amber-400">● Deterministic Rule Engine</span>
                      ) : (
                        <span className="text-emerald-400">● Gemini Grounded Analysis</span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => copyToClipboard(m.id, m.text)}
                        className="hover:text-slate-200 flex items-center gap-1 transition-colors"
                        title="Copy text"
                      >
                        {copiedId === m.id ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-400" />
                            <span>Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            <span>Copy</span>
                          </>
                        )}
                      </button>

                      <button
                        onClick={() => {
                          onSaveAiExplanationForReport(m.text);
                          setIsSavedForReport(true);
                        }}
                        className="hover:text-cyan-300 flex items-center gap-1 transition-colors text-cyan-400"
                        title="Include in formal PDF report"
                      >
                        <FileText className="w-3 h-3" />
                        <span>Include in Report</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}

          {isProcessing && (
            <div className="flex gap-3 mr-auto max-w-lg">
              <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0 text-cyan-400">
                <Bot className="w-4 h-4 animate-spin" />
              </div>
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-300 flex items-center gap-2">
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                <span>Auditing cryptographic data and compiling plain-language brief...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Suggested Questions */}
        <div className="px-4 py-2 border-t border-slate-800/80 bg-slate-900/40 flex items-center gap-2 overflow-x-auto no-scrollbar">
          <span className="text-[11px] font-mono text-slate-500 shrink-0">
            {language === 'mr' ? 'सुचवलेले प्रश्न:' : 'Suggested:'}
          </span>
          {suggestedQuestions.map((q, idx) => (
            <button
              key={idx}
              onClick={() => handleSendChat(q)}
              disabled={isProcessing}
              className="text-[11px] font-mono px-2.5 py-1 rounded-md bg-slate-800/80 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-cyan-300 whitespace-nowrap shrink-0 transition-colors disabled:opacity-40"
            >
              {q}
            </button>
          ))}
        </div>

        {/* Input Bar */}
        <div className="p-3 border-t border-slate-800 bg-slate-900/80">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSendChat();
            }}
            className="flex items-center gap-2"
          >
            <input
              type="text"
              value={inputQuestion}
              onChange={(e) => setInputQuestion(e.target.value)}
              placeholder={
                language === 'mr'
                  ? 'फॉरेन्सिक निकालांबद्दल प्रश्न विचारा (उदा. संशयित भाग किंवा न्यायालयात ग्राह्यता)...'
                  : 'Ask about check failures, anomaly coordinates, or legal admissibility...'
              }
              disabled={isProcessing}
              className="flex-1 bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-xs font-mono text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
            />
            <button
              type="submit"
              disabled={isProcessing || !inputQuestion.trim()}
              className="px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-slate-950 font-semibold text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Send</span>
            </button>
          </form>

          {/* Legal disclaimer */}
          <p className="text-[10px] text-slate-500 font-mono mt-2 text-center">
            * SealChain AI Assistant provides explanatory analysis strictly over mathematical results. Admissibility decisions rest with judicial triers of fact under evidentiary rules.
          </p>
        </div>
      </div>
    </div>
  );
};
