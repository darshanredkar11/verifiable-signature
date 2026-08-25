use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::claim::{Claim, ClaimSchema};
use crate::extract::{extract_claims, hash_claim};
use crate::merkle::{MerkleTree, root_hex, hash_leaf};
use crate::sdp_version::SDP_VERSION;

/// A semantic commitment: the signed Merkle root of a document's claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticCommitment {
    pub algorithm: String,
    pub commitment_id: String,
    pub schema_version: String,
    pub merkle_root: String,
    pub claim_count: usize,
    pub claim_keys: Vec<String>,
    pub signature: String,
    pub public_key: String,
    pub created_at: String,
    pub document_hash: String,
}

/// Result of committing a document.
#[derive(Debug)]
pub struct CommitResult {
    pub commitment: SemanticCommitment,
    pub claims: Vec<Claim>,
    pub tree: MerkleTree,
}

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

pub fn commit_document(
    document: &serde_json::Value,
    schema: &[ClaimSchema],
    signing_key: &SigningKey,
    schema_version: &str,
) -> CommitResult {
    let mut claims = extract_claims(document, schema);
    claims.sort_by(|a, b| a.canonical_key().cmp(&b.canonical_key()));

    let doc_bytes = serde_json::to_vec(document).unwrap();
    let mut doc_hasher = Sha256::new();
    doc_hasher.update(&doc_bytes);
    let document_hash = hex::encode(doc_hasher.finalize());

    let leaf_hashes: Vec<[u8; 32]> = claims.iter().map(|c| {
        let claim_hash = hash_claim(c);
        hash_leaf(&claim_hash)
    }).collect();

    let tree = MerkleTree::new(leaf_hashes);

    let commitment_id = format!(
        "sdp:{}:{}",
        hex::encode(&tree.root[..8]),
        Utc::now().format("%Y%m%d%H%M%S")
    );

    let signature = signing_key.sign(&tree.root);

    let claim_keys: Vec<String> = claims.iter().map(|c| c.canonical_key()).collect();

    let commitment = SemanticCommitment {
        algorithm: SDP_VERSION.to_string(),
        commitment_id,
        schema_version: schema_version.to_string(),
        merkle_root: root_hex(&tree),
        claim_count: claims.len(),
        claim_keys,
        signature: hex::encode(signature.to_bytes()),
        public_key: hex::encode(signing_key.verifying_key().to_bytes()),
        created_at: Utc::now().to_rfc3339(),
        document_hash,
    };

    CommitResult { commitment, claims, tree }
}

pub fn verify_commitment_signature(commitment: &SemanticCommitment) -> bool {
    let root_bytes = match hex::decode(&commitment.merkle_root) {
        Ok(h) if h.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            arr
        }
        _ => return false,
    };

    let sig_bytes = match hex::decode(&commitment.signature) {
        Ok(h) if h.len() == 64 => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&h);
            arr
        }
        _ => return false,
    };

    let pub_bytes = match hex::decode(&commitment.public_key) {
        Ok(h) if h.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            arr
        }
        _ => return false,
    };

    let Ok(verifying_key) = VerifyingKey::from_bytes(&pub_bytes) else {
        return false;
    };

    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    verifying_key.verify(&root_bytes, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::{ClaimCriticality, ClaimSchema, ValueType};

    fn test_schema() -> Vec<ClaimSchema> {
        vec![
            ClaimSchema {
                field_name: "tenant".to_string(),
                display_name: "Tenant".to_string(),
                criticality: ClaimCriticality::Normal,
                value_type: ValueType::Text,
            },
            ClaimSchema {
                field_name: "rent".to_string(),
                display_name: "Monthly Rent".to_string(),
                criticality: ClaimCriticality::Critical,
                value_type: ValueType::Currency,
            },
        ]
    }

    #[test]
    fn test_commit_and_verify() {
        let doc = serde_json::json!({
            "tenant": "Alice",
            "rent": "€1,500"
        });

        let (sk, _vk) = generate_keypair();
        let result = commit_document(&doc, &test_schema(), &sk, "1.0");

        assert!(verify_commitment_signature(&result.commitment));
        assert_eq!(result.claims.len(), 2);
        assert!(!result.commitment.merkle_root.is_empty());
    }
}
