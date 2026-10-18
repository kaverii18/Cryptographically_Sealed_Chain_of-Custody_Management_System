/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { MerkleProof, MerkleProofStep, MerkleTreeData, MerkleNodeInfo } from '../types/forensics';

/**
 * Computes SHA-256 hash of a string using the native Web Crypto API.
 */
export async function sha256Hex(text: string): Promise<string> {
  const enc = new TextEncoder();
  const buffer = await window.crypto.subtle.digest('SHA-256', enc.encode(text));
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Combines two SHA-256 hex strings in deterministic order (left + right)
 * and returns their parent SHA-256 hash.
 */
export async function combineHashes(left: string, right: string): Promise<string> {
  return sha256Hex(left + right);
}

export interface MerkleEvidenceInput {
  id: string;
  label: string;
  sha256Hash: string;
}

/**
 * Builds a complete Merkle tree over the list of evidence items.
 * Implements RFC 6962 / Bitcoin style leaf and internal node concatenation.
 * If a level has an odd number of nodes, duplicates the last node.
 */
export async function buildMerkleTree(items: MerkleEvidenceInput[]): Promise<MerkleTreeData> {
  if (items.length === 0) {
    const emptyRoot = await sha256Hex('EMPTY_SEALCHAIN_MERKLE_TREE');
    return {
      root: emptyRoot,
      leaves: [],
      levels: [[emptyRoot]],
      leafMap: {},
      nodes: [
        {
          id: 'node-0-0',
          hash: emptyRoot,
          level: 0,
          index: 0,
          isLeaf: true,
          label: 'Empty Tree',
        },
      ],
    };
  }

  const leaves = items.map((item) => item.sha256Hash);
  const leafMap: Record<string, { evidenceId: string; label: string; hash: string }> = {};
  items.forEach((item) => {
    leafMap[item.sha256Hash] = {
      evidenceId: item.id,
      label: item.label,
      hash: item.sha256Hash,
    };
  });

  const levels: string[][] = [];
  const nodes: MerkleNodeInfo[] = [];

  // Level 0: Leaves
  let currentLevel = [...leaves];
  levels.push([...currentLevel]);

  currentLevel.forEach((hash, idx) => {
    const item = items[idx];
    nodes.push({
      id: `leaf-${idx}`,
      hash,
      level: 0,
      index: idx,
      isLeaf: true,
      label: item ? item.label : `Evidence #${idx + 1}`,
      evidenceId: item ? item.id : undefined,
    });
  });

  let levelIdx = 0;
  while (currentLevel.length > 1) {
    const nextLevel: string[] = [];
    levelIdx++;

    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left; // duplicate if odd

      const parentHash = await combineHashes(left, right);
      nextLevel.push(parentHash);

      nodes.push({
        id: `node-${levelIdx}-${Math.floor(i / 2)}`,
        hash: parentHash,
        level: levelIdx,
        index: Math.floor(i / 2),
        isLeaf: false,
        label: `Parent L${levelIdx} [${i / 2}]`,
        leftChildId: levelIdx === 1 ? `leaf-${i}` : `node-${levelIdx - 1}-${i}`,
        rightChildId:
          levelIdx === 1
            ? i + 1 < currentLevel.length
              ? `leaf-${i + 1}`
              : `leaf-${i}`
            : i + 1 < currentLevel.length
            ? `node-${levelIdx - 1}-${i + 1}`
            : `node-${levelIdx - 1}-${i}`,
      });
    }

    levels.push([...nextLevel]);
    currentLevel = nextLevel;
  }

  const root = currentLevel[0] || '';

  return {
    root,
    leaves,
    levels,
    leafMap,
    nodes,
  };
}

/**
 * Generates an inclusion proof (path of sibling hashes from leaf to root)
 * for a specific evidence specimen in the Merkle tree.
 */
export async function generateMerkleProof(
  tree: MerkleTreeData,
  leafIndex: number,
  evidenceId: string,
  label: string
): Promise<MerkleProof | null> {
  if (leafIndex < 0 || leafIndex >= tree.leaves.length) {
    return null;
  }

  const leafHash = tree.leaves[leafIndex];
  const proofSteps: MerkleProofStep[] = [];
  let currentIndex = leafIndex;

  for (let lvl = 0; lvl < tree.levels.length - 1; lvl++) {
    const levelHashes = tree.levels[lvl];
    const isRightChild = currentIndex % 2 === 1;
    const siblingIndex = isRightChild ? currentIndex - 1 : currentIndex + 1;

    let siblingHash: string;
    if (siblingIndex < levelHashes.length) {
      siblingHash = levelHashes[siblingIndex];
    } else {
      // Duplicated odd node
      siblingHash = levelHashes[currentIndex];
    }

    proofSteps.push({
      siblingHash,
      position: isRightChild ? 'left' : 'right',
    });

    currentIndex = Math.floor(currentIndex / 2);
  }

  // Self-verify the proof
  const isVerified = await verifyMerkleProof(leafHash, tree.root, proofSteps);

  return {
    evidenceId,
    label,
    leafHash,
    rootHash: tree.root,
    proof: proofSteps,
    isVerified,
  };
}

/**
 * Cryptographically verifies a Merkle proof:
 * Starting from the leaf hash, traverses up applying siblings.
 * Returns true if the calculated root matches the expected root.
 */
export async function verifyMerkleProof(
  leafHash: string,
  expectedRoot: string,
  proof: MerkleProofStep[]
): Promise<boolean> {
  let currentHash = leafHash;

  for (const step of proof) {
    if (step.position === 'left') {
      currentHash = await combineHashes(step.siblingHash, currentHash);
    } else {
      currentHash = await combineHashes(currentHash, step.siblingHash);
    }
  }

  return currentHash.toLowerCase() === expectedRoot.toLowerCase();
}
