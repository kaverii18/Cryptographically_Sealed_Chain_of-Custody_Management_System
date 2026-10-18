/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { UserProfile, UserRole } from '../types/forensics';
import { generateECDSAKeyPair } from '../crypto/webCrypto';

const RBAC_USERS_STORAGE_KEY = 'SEALCHAIN_RBAC_USERS';
const RBAC_ACTIVE_USER_ID_KEY = 'SEALCHAIN_RBAC_ACTIVE_USER_ID';

export interface RolePermissionDetails {
  allowed: boolean;
  reason?: string;
}

/**
 * Pre-defined demographic profiles for the three core digital forensics roles.
 */
const DEMO_USER_CONFIGS = [
  {
    id: 'user-collector-01',
    username: 'mcruz_csu',
    name: 'Det. Marcus Cruz',
    role: 'COLLECTOR' as UserRole,
    title: 'Senior Evidence Intake Officer',
    agency: 'Metropolitan Police Dept — Crime Scene CSU',
    badge: 'BADGE #CSU-4409',
    avatarColor: 'from-amber-600 to-orange-700',
  },
  {
    id: 'user-analyst-01',
    username: 'erostova_dfir',
    name: 'Dr. Elena Rostova',
    role: 'ANALYST' as UserRole,
    title: 'Lead Forensic Cryptographer & Technical Analyst',
    agency: 'State Bureau of Investigation — Cyber Forensic Lab',
    badge: 'FED-CRED #DFIR-8820',
    avatarColor: 'from-cyan-600 to-blue-700',
  },
  {
    id: 'user-judge-01',
    username: 'pvance_court',
    name: 'Hon. Patricia Vance',
    role: 'JUDGE' as UserRole,
    title: 'District Magistrate / Admissibility Reviewer',
    agency: '4th Judicial Circuit Court of Appeals',
    badge: 'ROBE #JUD-0129',
    avatarColor: 'from-purple-600 to-indigo-800',
  },
];

/**
 * Initializes or loads persistent ECDSA P-256 keypairs for each demo user.
 */
export async function initializeRbacUsers(): Promise<UserProfile[]> {
  try {
    const raw = localStorage.getItem(RBAC_USERS_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as UserProfile[];
      if (Array.isArray(parsed) && parsed.length === DEMO_USER_CONFIGS.length) {
        return parsed;
      }
    }
  } catch (err) {
    console.warn('Failed to load RBAC users from localStorage, generating fresh:', err);
  }

  // Generate authentic Web Crypto ECDSA keypairs for each user
  const users: UserProfile[] = [];
  for (const cfg of DEMO_USER_CONFIGS) {
    const keyPair = await generateECDSAKeyPair();
    users.push({
      ...cfg,
      publicKeyJwk: keyPair.publicKeyJwk,
      privateKeyJwk: keyPair.privateKeyJwk,
    });
  }

  try {
    localStorage.setItem(RBAC_USERS_STORAGE_KEY, JSON.stringify(users));
  } catch (err) {
    console.error('Failed to persist RBAC users:', err);
  }

  return users;
}

/**
 * Retrieves the currently active user profile.
 */
export function getActiveUserId(): string {
  return localStorage.getItem(RBAC_ACTIVE_USER_ID_KEY) || 'user-analyst-01'; // Default to Analyst for full capability demo
}

/**
 * Sets the currently active user profile ID.
 */
export function setActiveUserId(userId: string): void {
  localStorage.setItem(RBAC_ACTIVE_USER_ID_KEY, userId);
}

/**
 * Comprehensive permission checks per user role.
 */
export const RbacPermissions = {
  canAddEvidence(role: UserRole): RolePermissionDetails {
    if (role === 'COLLECTOR' || role === 'ANALYST') {
      return { allowed: true };
    }
    return {
      allowed: false,
      reason: 'Judges and read-only viewers cannot ingest or modify evidence specimens in active cases.',
    };
  },

  canAppendCustodyEvent(role: UserRole): RolePermissionDetails {
    if (role === 'COLLECTOR' || role === 'ANALYST') {
      return { allowed: true };
    }
    return {
      allowed: false,
      reason: 'Judges and read-only viewers cannot append custody transfer or storage blocks.',
    };
  },

  canRunSteganography(role: UserRole): RolePermissionDetails {
    if (role === 'ANALYST') {
      return { allowed: true };
    }
    return {
      allowed: false,
      reason:
        role === 'COLLECTOR'
          ? 'Collectors are restricted from cryptographic stego embedding. Only authorized Forensic Analysts can seal fragile payloads.'
          : 'Judges have read-only audit permissions and cannot embed steganographic payloads.',
    };
  },

  canRunWatermarking(role: UserRole): RolePermissionDetails {
    if (role === 'ANALYST') {
      return { allowed: true };
    }
    return {
      allowed: false,
      reason:
        role === 'COLLECTOR'
          ? 'Collectors are restricted from DCT watermark modulation. Only authorized Forensic Analysts can apply cryptographic watermarks.'
          : 'Judges have read-only audit permissions and cannot apply watermarks.',
    };
  },

  canRunVerification(role: UserRole): RolePermissionDetails {
    if (role === 'ANALYST') {
      return { allowed: true };
    }
    return {
      allowed: false,
      reason:
        role === 'COLLECTOR'
          ? 'Intake Collectors cannot execute the 5-check forensic verification suite. Consult a Forensic Analyst.'
          : 'Judges review court-admissible verification verdicts but cannot execute automated analysis suites directly.',
    };
  },

  canSealCaseMerkle(role: UserRole): RolePermissionDetails {
    if (role === 'ANALYST') {
      return { allowed: true };
    }
    return {
      allowed: false,
      reason: 'Only certified Forensic Analysts can execute case-wide Merkle Tree cryptographic seals.',
    };
  },

  canGenerateReport(role: UserRole): RolePermissionDetails {
    if (role === 'ANALYST') {
      return { allowed: true };
    }
    return {
      allowed: false,
      reason: 'Official court-admissible forensic PDF reports must be compiled and signed by a certified Forensic Analyst.',
    };
  },

  canTamperDemo(role: UserRole): RolePermissionDetails {
    if (role === 'ANALYST') {
      return { allowed: true };
    }
    return {
      allowed: false,
      reason: 'Simulated tampering attacks are restricted to certified Forensic Analysts in the testing lab.',
    };
  },

  canVerifyReport(role: UserRole): RolePermissionDetails {
    // All roles can verify reports
    return { allowed: true };
  },

  canUseAiAssistant(role: UserRole): RolePermissionDetails {
    // All roles can ask questions to understand findings
    return { allowed: true };
  },
};
