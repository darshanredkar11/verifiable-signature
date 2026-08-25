pub mod api;
pub mod claim;
pub mod commit;
pub mod delta;
pub mod extract;
pub mod ffi;
pub mod merkle;
pub mod sdp_version;

pub use claim::{Claim, ChangeClassification, ChangeType, ClaimCriticality, ClaimSchema, ValueType};
pub use commit::{SemanticCommitment, CommitResult, generate_keypair, commit_document, verify_commitment_signature};
pub use delta::{SemanticDeltaProof, ClaimDelta, IntegrityResult, compute_delta, verify_delta_proofs, DeltaVerificationResult};
pub use extract::{extract_claims, hash_claim, hash_claims, normalize_value};
pub use merkle::{MerkleTree, MerkleInclusionProof, ProofStep, ProofPosition, hash_leaf, hash_internal, root_hex};
pub use sdp_version::{SDP_VERSION, ALGORITHM_NAME, ALGORITHM_VERSION};
