use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::claim::{ChangeClassification, ChangeType, Claim, ClaimSchema};
use crate::commit::SemanticCommitment;
use crate::extract::{extract_claims, hash_claim};
use crate::merkle::{MerkleInclusionProof, MerkleTree, hash_leaf, root_hex};

/// Complete semantic delta proof between two documents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticDeltaProof {
    pub status: ChangeClassification,
    pub original_commitment: SemanticCommitment,
    pub current_commitment: String,
    pub byte_integrity: IntegrityResult,
    pub semantic_integrity: IntegrityResult,
    pub changes: Vec<ClaimDelta>,
    pub unchanged_count: usize,
    pub original_claim_count: usize,
    pub current_claim_count: usize,
    pub original_commitment_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityResult {
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimDelta {
    pub claim: Claim,
    pub original_value: Option<String>,
    pub current_value: Option<String>,
    pub change_type: ChangeType,
    pub classification: ChangeClassification,
    pub original_merkle_proof: Option<MerkleInclusionProof>,
    pub current_merkle_proof: Option<MerkleInclusionProof>,
}

pub fn compute_delta(
    original_claims: &[Claim],
    original_tree: &MerkleTree,
    original_commitment: &SemanticCommitment,
    current_document: &serde_json::Value,
    schema: &[ClaimSchema],
    original_doc_hash: &str,
) -> SemanticDeltaProof {
    let mut current_claims = extract_claims(current_document, schema);
    current_claims.sort_by(|a, b| a.canonical_key().cmp(&b.canonical_key()));

    let current_leaves: Vec<[u8; 32]> = current_claims.iter().map(|c| {
        let claim_hash = hash_claim(c);
        hash_leaf(&claim_hash)
    }).collect();
    let current_tree = MerkleTree::new(current_leaves);

    // Byte-level integrity check
    let current_doc_bytes = serde_json::to_vec(current_document).unwrap();
    let mut current_doc_hasher = Sha256::new();
    current_doc_hasher.update(&current_doc_bytes);
    let current_doc_hash = hex::encode(current_doc_hasher.finalize());

    let byte_integrity = if current_doc_hash == original_doc_hash {
        IntegrityResult { passed: true, detail: "Document bytes are identical".to_string() }
    } else {
        IntegrityResult { passed: false, detail: "Document bytes differ".to_string() }
    };

    // Semantic integrity check
    let semantic_integrity = if original_tree.root == current_tree.root {
        IntegrityResult { passed: true, detail: "Semantic commitment is identical".to_string() }
    } else {
        IntegrityResult { passed: false, detail: "Semantic commitment differs".to_string() }
    };

    // Build claim index maps, keyed by claim IDENTITY (subject|predicate), not by
    // the value-inclusive canonical_key — otherwise a changed value looks like an
    // unrelated remove+add instead of a modification, and CRITICAL_CHANGE never fires.
    let original_map: std::collections::HashMap<String, (usize, Claim)> = original_claims
        .iter()
        .enumerate()
        .map(|(i, c)| (c.identity_key(), (i, c.clone())))
        .collect();
    let current_map: std::collections::HashMap<String, (usize, Claim)> = current_claims
        .iter()
        .enumerate()
        .map(|(i, c)| (c.identity_key(), (i, c.clone())))
        .collect();

    let mut changes = Vec::new();
    let mut unchanged_count = 0;

    for (key, (orig_idx, ref orig_claim)) in &original_map {
        match current_map.get(key) {
            Some((curr_idx, ref curr_claim)) => {
                if orig_claim.value == curr_claim.value {
                    unchanged_count += 1;
                } else {
                    let classification = classify_change(
                        orig_claim,
                        &orig_claim.value,
                        &curr_claim.value,
                    );

                    let orig_proof = original_tree.prove(*orig_idx);
                    let curr_proof = current_tree.prove(*curr_idx);

                    changes.push(ClaimDelta {
                        claim: orig_claim.clone(),
                        original_value: Some(orig_claim.value.clone()),
                        current_value: Some(curr_claim.value.clone()),
                        change_type: ChangeType::Modified,
                        classification,
                        original_merkle_proof: orig_proof,
                        current_merkle_proof: curr_proof,
                    });
                }
            }
            None => {
                let orig_proof = original_tree.prove(*orig_idx);
                changes.push(ClaimDelta {
                    claim: orig_claim.clone(),
                    original_value: Some(orig_claim.value.clone()),
                    current_value: None,
                    change_type: ChangeType::Removed,
                    classification: ChangeClassification::SemanticChange,
                    original_merkle_proof: orig_proof,
                    current_merkle_proof: None,
                });
            }
        }
    }

    for (key, (curr_idx, ref curr_claim)) in &current_map {
        if !original_map.contains_key(key) {
            let curr_proof = current_tree.prove(*curr_idx);
            changes.push(ClaimDelta {
                claim: curr_claim.clone(),
                original_value: None,
                current_value: Some(curr_claim.value.clone()),
                change_type: ChangeType::Added,
                classification: ChangeClassification::SemanticChange,
                original_merkle_proof: None,
                current_merkle_proof: curr_proof,
            });
        }
    }

    let mut status = determine_overall_classification(&changes);
    // No claim-level changes but the bytes differ (reformatting, OCR, PDF/A, re-export,
    // metadata rewrite, ...): semantics are identical, representation is not — that is
    // SEMANTICALLY_EQUIVALENT, distinct from byte-for-byte UNCHANGED.
    if status == ChangeClassification::Unchanged && !byte_integrity.passed {
        status = ChangeClassification::SemanticallyEquivalent;
    }
    let original_valid = crate::commit::verify_commitment_signature(original_commitment);

    SemanticDeltaProof {
        status,
        original_commitment: original_commitment.clone(),
        current_commitment: root_hex(&current_tree),
        byte_integrity,
        semantic_integrity,
        changes,
        unchanged_count,
        original_claim_count: original_claims.len(),
        current_claim_count: current_claims.len(),
        original_commitment_valid: original_valid,
    }
}

fn classify_change(
    claim: &Claim,
    original_value: &str,
    current_value: &str,
) -> ChangeClassification {
    let orig_normalized = crate::extract::normalize_value(original_value, &crate::claim::ValueType::Text);
    let curr_normalized = crate::extract::normalize_value(current_value, &crate::claim::ValueType::Text);

    if orig_normalized == curr_normalized {
        return ChangeClassification::FormatOnly;
    }

    if claim.predicate == "has_value" && looks_like_currency(original_value) {
        let (orig_amount, orig_currency) = parse_currency_simple(original_value);
        let (curr_amount, curr_currency) = parse_currency_simple(current_value);

        if orig_amount == curr_amount && orig_currency == curr_currency {
            return ChangeClassification::FormatOnly;
        }
        if orig_currency == curr_currency && orig_amount != curr_amount {
            return ChangeClassification::CriticalChange;
        }
        return ChangeClassification::CriticalChange;
    }

    ChangeClassification::SemanticChange
}

fn parse_currency_simple(s: &str) -> (f64, String) {
    let s = s.trim();

    if s.contains('€') {
        let num: String = s.chars().filter(|c| c.is_ascii_digit() || *c == '.' || *c == '-').collect();
        return (num.parse().unwrap_or(0.0), "EUR".to_string());
    }
    if s.contains('$') {
        let num: String = s.chars().filter(|c| c.is_ascii_digit() || *c == '.' || *c == '-').collect();
        return (num.parse().unwrap_or(0.0), "USD".to_string());
    }

    for code in &["EUR", "USD", "GBP", "JPY"] {
        if s.contains(code) {
            let num: String = s.chars().filter(|c| c.is_ascii_digit() || *c == '.' || *c == '-').collect();
            return (num.parse().unwrap_or(0.0), code.to_string());
        }
    }

    (0.0, "UNKNOWN".to_string())
}

fn looks_like_currency(s: &str) -> bool {
    s.contains('€') || s.contains('$') || s.contains('£')
        || s.contains("EUR") || s.contains("USD") || s.contains("GBP")
}

fn determine_overall_classification(changes: &[ClaimDelta]) -> ChangeClassification {
    if changes.is_empty() {
        return ChangeClassification::Unchanged;
    }

    if changes.iter().any(|c| matches!(c.classification, ChangeClassification::CriticalChange)) {
        return ChangeClassification::CriticalChange;
    }
    if changes.iter().any(|c| matches!(c.classification, ChangeClassification::SemanticChange)) {
        return ChangeClassification::SemanticChange;
    }
    if changes.iter().all(|c| matches!(
        c.classification,
        ChangeClassification::FormatOnly | ChangeClassification::SemanticallyEquivalent
    )) {
        return ChangeClassification::SemanticallyEquivalent;
    }

    ChangeClassification::SemanticChange
}

pub fn verify_delta_proofs(proof: &SemanticDeltaProof) -> DeltaVerificationResult {
    let mut details = Vec::new();
    let mut all_valid = true;

    let orig_root = match hex::decode(&proof.original_commitment.merkle_root) {
        Ok(h) if h.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            arr
        }
        _ => return DeltaVerificationResult { valid: false, details: vec!["Invalid original Merkle root".to_string()] },
    };

    let curr_root = match hex::decode(&proof.current_commitment) {
        Ok(h) if h.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            arr
        }
        _ => return DeltaVerificationResult { valid: false, details: vec!["Invalid current Merkle root".to_string()] },
    };

    for change in &proof.changes {
        if let Some(ref orig_proof) = change.original_merkle_proof {
            let valid = MerkleTree::verify_proof(orig_proof, &orig_root);
            if !valid {
                all_valid = false;
                details.push(format!("INVALID original proof for: {}", change.claim.canonical_key()));
            } else {
                details.push(format!("VALID original proof for: {}", change.claim.canonical_key()));
            }
        }
        if let Some(ref curr_proof) = change.current_merkle_proof {
            let valid = MerkleTree::verify_proof(curr_proof, &curr_root);
            if !valid {
                all_valid = false;
                details.push(format!("INVALID current proof for: {}", change.claim.canonical_key()));
            } else {
                details.push(format!("VALID current proof for: {}", change.claim.canonical_key()));
            }
        }
    }

    let sig_valid = crate::commit::verify_commitment_signature(&proof.original_commitment);
    if !sig_valid {
        all_valid = false;
        details.push("INVALID original commitment signature".to_string());
    } else {
        details.push("VALID original commitment signature".to_string());
    }

    DeltaVerificationResult { valid: all_valid, details }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaVerificationResult {
    pub valid: bool,
    pub details: Vec<String>,
}
