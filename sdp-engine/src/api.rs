//! Shared entry points used by both the CLI binary (`src/bin/sdp-engine.rs`) and the
//! C-ABI FFI layer (`src/ffi.rs`). Both callers pass plain JSON strings in and get a
//! JSON string back — this module is the single place that turns request JSON into
//! calls against the deterministic core (extract/claim/merkle/commit/delta) and back
//! into response JSON, so the CLI and the FFI boundary can never drift apart.

use serde_json::{json, Value};

use crate::{
    commit_document, compute_delta, generate_keypair, hash_claim, hash_leaf, root_hex, Claim,
    ClaimSchema, MerkleInclusionProof, MerkleTree, ProofPosition, SemanticCommitment,
};

fn parse_schema(v: &Value) -> Result<Vec<ClaimSchema>, String> {
    serde_json::from_value(v.clone()).map_err(|e| format!("invalid schema: {}", e))
}

fn claim_json(c: &Claim) -> Value {
    json!({ "subject": c.subject, "predicate": c.predicate, "value": c.value })
}

fn proof_json(p: &MerkleInclusionProof) -> Value {
    json!({
        "leafHash": p.leaf_hash,
        "leafIndex": p.leaf_index,
        "path": p.path.iter().map(|s| json!({
            "hash": s.hash,
            "position": match s.position { ProofPosition::Left => "left", ProofPosition::Right => "right" }
        })).collect::<Vec<_>>(),
        "root": p.root,
        "treeSize": p.tree_size,
    })
}

fn commitment_json(c: &SemanticCommitment) -> Value {
    json!({
        "algorithm": c.algorithm,
        "commitmentId": c.commitment_id,
        "schemaVersion": c.schema_version,
        "merkleRoot": c.merkle_root,
        "claimCount": c.claim_count,
        "claimKeys": c.claim_keys,
        "signature": c.signature,
        "publicKey": c.public_key,
        "createdAt": c.created_at,
        "documentHash": c.document_hash,
    })
}

fn parse_commitment_and_claims(v: &Value) -> Result<(SemanticCommitment, Vec<Claim>), String> {
    let get_str = |k: &str| -> Result<String, String> {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(String::from)
            .ok_or_else(|| format!("commitment missing field '{}'", k))
    };
    let commitment = SemanticCommitment {
        algorithm: get_str("algorithm")?,
        commitment_id: get_str("commitmentId")?,
        schema_version: get_str("schemaVersion")?,
        merkle_root: get_str("merkleRoot")?,
        claim_count: v.get("claimCount").and_then(|x| x.as_u64()).unwrap_or(0) as usize,
        claim_keys: v
            .get("claimKeys")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|e| e.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        signature: get_str("signature")?,
        public_key: get_str("publicKey")?,
        created_at: get_str("createdAt")?,
        document_hash: get_str("documentHash")?,
    };

    let claims: Vec<Claim> = v
        .get("claims")
        .and_then(|x| x.as_array())
        .ok_or_else(|| "commitment missing 'claims' array — cannot reconstruct original claim set".to_string())?
        .iter()
        .map(|c| Claim {
            subject: c.get("subject").and_then(|s| s.as_str()).unwrap_or("").to_string(),
            predicate: c.get("predicate").and_then(|s| s.as_str()).unwrap_or("").to_string(),
            value: c.get("value").and_then(|s| s.as_str()).unwrap_or("").to_string(),
        })
        .collect();

    Ok((commitment, claims))
}

/// Generate a fresh Ed25519 keypair. Returns "<privkey_hex> <pubkey_hex>".
pub fn api_generate_keypair() -> String {
    let (sk, vk) = generate_keypair();
    format!("{} {}", hex::encode(sk.to_bytes()), hex::encode(vk.to_bytes()))
}

/// Commit a document: extract claims, canonicalize, build the Merkle tree, sign the root.
/// Returns a JSON commitment string (including the full claim list, needed later by `api_verify`
/// to reconstruct the original tree without re-transmitting the raw original document).
pub fn api_commit(doc_json: &str, schema_json: &str, privkey_hex: &str, schema_version: &str) -> Result<String, String> {
    let doc_val: Value = serde_json::from_str(doc_json).map_err(|e| format!("invalid document JSON: {}", e))?;
    let schema_val: Value = serde_json::from_str(schema_json).map_err(|e| format!("invalid schema JSON: {}", e))?;
    let schema_list = parse_schema(&schema_val)?;

    let priv_bytes = hex::decode(privkey_hex).map_err(|e| format!("invalid privkey hex: {}", e))?;
    if priv_bytes.len() != 32 {
        return Err("privkey must be 32 bytes (64 hex chars)".to_string());
    }
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&priv_bytes);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&sk_arr);

    let result = commit_document(&doc_val, &schema_list, &signing_key, schema_version);

    let mut out = commitment_json(&result.commitment);
    out["claims"] = Value::Array(result.claims.iter().map(claim_json).collect());
    Ok(out.to_string())
}

/// Verify a current document representation against a signed original commitment.
/// Returns a JSON `SemanticDeltaProof` string with the classification and per-claim
/// Merkle inclusion proofs for every changed claim.
pub fn api_verify(doc_json: &str, schema_json: &str, commitment_json_str: &str) -> Result<String, String> {
    let doc_val: Value = serde_json::from_str(doc_json).map_err(|e| format!("invalid document JSON: {}", e))?;
    let schema_val: Value = serde_json::from_str(schema_json).map_err(|e| format!("invalid schema JSON: {}", e))?;
    let schema_list = parse_schema(&schema_val)?;
    let commitment_val: Value = serde_json::from_str(commitment_json_str).map_err(|e| format!("invalid commitment JSON: {}", e))?;
    let (original_commitment, original_claims) = parse_commitment_and_claims(&commitment_val)?;

    let original_leaves: Vec<[u8; 32]> = original_claims.iter().map(|c| hash_leaf(&hash_claim(c))).collect();
    let original_tree = MerkleTree::new(original_leaves);

    if root_hex(&original_tree) != original_commitment.merkle_root {
        return Err("commitment integrity check failed: claim set does not reproduce the signed Merkle root (possible tampering)".to_string());
    }

    let proof = compute_delta(
        &original_claims,
        &original_tree,
        &original_commitment,
        &doc_val,
        &schema_list,
        &original_commitment.document_hash,
    );

    let out = json!({
        "status": proof.status.to_string(),
        "originalCommitment": commitment_json(&proof.original_commitment),
        "currentCommitment": proof.current_commitment,
        "byteIntegrity": { "passed": proof.byte_integrity.passed, "detail": proof.byte_integrity.detail },
        "semanticIntegrity": { "passed": proof.semantic_integrity.passed, "detail": proof.semantic_integrity.detail },
        "originalCommitmentValid": proof.original_commitment_valid,
        "unchangedCount": proof.unchanged_count,
        "originalClaimCount": proof.original_claim_count,
        "currentClaimCount": proof.current_claim_count,
        "changes": proof.changes.iter().map(|ch| json!({
            "claim": claim_json(&ch.claim),
            "originalValue": ch.original_value,
            "currentValue": ch.current_value,
            "changeType": match ch.change_type {
                crate::ChangeType::Added => "ADDED",
                crate::ChangeType::Removed => "REMOVED",
                crate::ChangeType::Modified => "MODIFIED",
            },
            "classification": ch.classification.to_string(),
            "originalMerkleProof": ch.original_merkle_proof.as_ref().map(proof_json),
            "currentMerkleProof": ch.current_merkle_proof.as_ref().map(proof_json),
        })).collect::<Vec<_>>(),
    });
    Ok(out.to_string())
}
