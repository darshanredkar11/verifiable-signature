use sha2::{Digest, Sha256};

/// A Merkle tree built over claim hashes.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub leaves: Vec<[u8; 32]>,
    pub nodes: Vec<[u8; 32]>,
    pub root: [u8; 32],
    pub depth: usize,
}

/// A Merkle inclusion proof for a single leaf.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleInclusionProof {
    pub leaf_hash: String,
    pub leaf_index: usize,
    pub path: Vec<ProofStep>,
    pub root: String,
    pub tree_size: usize,
}

/// A single step in a Merkle proof path.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofStep {
    pub hash: String,
    pub position: ProofPosition,
}

/// Position of sibling in the proof path.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ProofPosition {
    Left,
    Right,
}

impl MerkleTree {
    /// Build a Merkle tree from a list of leaf hashes.
    /// Uses SHA-256 with domain separation for internal nodes.
    pub fn new(leaves: Vec<[u8; 32]>) -> Self {
        if leaves.is_empty() {
            return Self {
                leaves: vec![],
                nodes: vec![],
                root: [0u8; 32],
                depth: 0,
            };
        }

        let depth = calculate_depth(leaves.len());
        let padded_size = 1 << depth;
        let mut padded_leaves = leaves.clone();
        // Pad to power of 2 by duplicating last leaf
        while padded_leaves.len() < padded_size {
            let last = *padded_leaves.last().unwrap();
            padded_leaves.push(last);
        }

        let mut nodes = Vec::new();
        // Build tree bottom-up
        let mut current_level = padded_leaves.clone();
        nodes.extend(&current_level);

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for pair in current_level.chunks(2) {
                let internal_hash = hash_internal(pair[0], pair[1]);
                next_level.push(internal_hash);
                nodes.push(internal_hash);
            }
            current_level = next_level;
        }

        let root = current_level[0];

        Self {
            leaves: padded_leaves,
            nodes,
            root,
            depth,
        }
    }

    /// Generate an inclusion proof for the leaf at the given index.
    pub fn prove(&self, leaf_index: usize) -> Option<MerkleInclusionProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let mut path = Vec::new();
        let mut current_index = leaf_index;
        let mut level_size = self.leaves.len();
        let mut level_offset = 0;

        // Navigate up the tree
        while level_size > 1 {
            let is_right = current_index % 2 == 1;
            let sibling_index = if is_right {
                current_index - 1
            } else {
                current_index + 1
            };

            if sibling_index < level_size {
                let sibling_hash = self.nodes[level_offset + sibling_index];
                path.push(ProofStep {
                    hash: hex::encode(sibling_hash),
                    position: if is_right {
                        ProofPosition::Left
                    } else {
                        ProofPosition::Right
                    },
                });
            }

            // Move to parent level
            current_index /= 2;
            level_offset += level_size;
            level_size /= 2;
        }

        Some(MerkleInclusionProof {
            leaf_hash: hex::encode(self.leaves[leaf_index]),
            leaf_index,
            path,
            root: hex::encode(self.root),
            tree_size: self.leaves.len(),
        })
    }

    /// Verify a Merkle inclusion proof against this tree's root.
    pub fn verify_proof(proof: &MerkleInclusionProof, root: &[u8; 32]) -> bool {
        let mut current_hash = match hex::decode(&proof.leaf_hash) {
            Ok(h) if h.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&h);
                arr
            }
            _ => return false,
        };

        for step in &proof.path {
            let sibling = match hex::decode(&step.hash) {
                Ok(h) if h.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&h);
                    arr
                }
                _ => return false,
            };

            current_hash = match step.position {
                ProofPosition::Left => hash_internal(sibling, current_hash),
                ProofPosition::Right => hash_internal(current_hash, sibling),
            };
        }

        current_hash == *root
    }
}

/// Calculate the depth (height) of a Merkle tree for n leaves.
fn calculate_depth(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    let mut depth = 0;
    let mut size = 1;
    while size < n {
        size <<= 1;
        depth += 1;
    }
    depth
}

/// Hash two child nodes to produce an internal node.
/// Uses domain separation: "SDP:internal:" prefix.
pub fn hash_internal(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SDP:internal:");
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Hash a leaf value for the Merkle tree.
/// Uses domain separation: "SDP:leaf:" prefix.
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SDP:leaf:");
    hasher.update(data);
    hasher.finalize().into()
}

/// Get the Merkle root as a hex string.
pub fn root_hex(tree: &MerkleTree) -> String {
    hex::encode(tree.root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_single_leaf() {
        let leaf = hash_leaf(b"test");
        let tree = MerkleTree::new(vec![leaf]);
        assert_eq!(tree.root, leaf);
        assert_eq!(tree.depth, 0);
    }

    #[test]
    fn test_merkle_two_leaves() {
        let l1 = hash_leaf(b"a");
        let l2 = hash_leaf(b"b");
        let tree = MerkleTree::new(vec![l1, l2]);
        assert_eq!(tree.depth, 1);
        let expected_root = hash_internal(l1, l2);
        assert_eq!(tree.root, expected_root);
    }

    #[test]
    fn test_merkle_proof_roundtrip() {
        let leaves: Vec<[u8; 32]> = (0..5)
            .map(|i| hash_leaf(format!("claim_{}", i).as_bytes()))
            .collect();
        let tree = MerkleTree::new(leaves);

        for i in 0..tree.leaves.len() {
            let proof = tree.prove(i).unwrap();
            assert!(
                MerkleTree::verify_proof(&proof, &tree.root),
                "Proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_merkle_proof_invalid() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| hash_leaf(format!("claim_{}", i).as_bytes()))
            .collect();
        let tree = MerkleTree::new(leaves);

        let proof = tree.prove(0).unwrap();
        let wrong_root = [0xFFu8; 32];
        assert!(!MerkleTree::verify_proof(&proof, &wrong_root));
    }

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::new(vec![]);
        assert_eq!(tree.root, [0u8; 32]);
        assert_eq!(tree.depth, 0);
    }
}
