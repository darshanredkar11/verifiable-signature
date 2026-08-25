use serde::{Deserialize, Serialize};

/// SDP-1 Algorithm version
pub const SDP_VERSION: &str = "sdp-1";

/// A semantic claim extracted from a document.
/// Subject | Predicate | Value triple.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Claim {
    pub subject: String,
    pub predicate: String,
    pub value: String,
}

impl Claim {
    pub fn new(subject: &str, predicate: &str, value: &str) -> Self {
        Self {
            subject: subject.to_string(),
            predicate: predicate.to_string(),
            value: value.to_string(),
        }
    }

    /// Canonical form for hashing: "subject|predicate|value" (lowercase, trimmed).
    /// This is what goes into the Merkle tree — a distinct value produces a distinct leaf.
    pub fn canonical_key(&self) -> String {
        format!(
            "{}|{}|{}",
            canonicalize_string(&self.subject),
            canonicalize_string(&self.predicate),
            canonicalize_string(&self.value)
        )
    }

    /// Identity key for matching the *same claim slot* across document versions:
    /// "subject|predicate" (no value). Used to detect MODIFIED vs ADDED/REMOVED —
    /// two claims with the same identity but different values are a modification,
    /// not an unrelated removal-plus-addition.
    pub fn identity_key(&self) -> String {
        format!(
            "{}|{}",
            canonicalize_string(&self.subject),
            canonicalize_string(&self.predicate)
        )
    }
}

/// Classification of change severity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChangeClassification {
    Unchanged,
    FormatOnly,
    SemanticallyEquivalent,
    SemanticChange,
    CriticalChange,
}

impl std::fmt::Display for ChangeClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unchanged => write!(f, "UNCHANGED"),
            Self::FormatOnly => write!(f, "FORMAT_ONLY"),
            Self::SemanticallyEquivalent => write!(f, "SEMANTICALLY_EQUIVALENT"),
            Self::SemanticChange => write!(f, "SEMANTIC_CHANGE"),
            Self::CriticalChange => write!(f, "CRITICAL_CHANGE"),
        }
    }
}

/// Classification of a claim's importance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ClaimCriticality {
    Normal,
    Critical,
}

/// A single change detected between two claim sets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimDelta {
    pub claim: Claim,
    pub original_value: Option<String>,
    pub current_value: Option<String>,
    pub change_type: ChangeType,
    pub classification: ChangeClassification,
    pub original_merkle_proof: Option<Vec<String>>,
    pub current_merkle_proof: Option<Vec<String>>,
    pub original_leaf_index: Option<usize>,
    pub current_leaf_index: Option<usize>,
}

/// Type of change to a claim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangeType {
    Added,
    Removed,
    Modified,
}

/// Schema definition for a document type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimSchema {
    pub field_name: String,
    pub display_name: String,
    pub criticality: ClaimCriticality,
    pub value_type: ValueType,
}

/// Expected value type for a claim field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ValueType {
    Text,
    Currency,
    Date,
    Number,
    Email,
}

impl std::fmt::Display for ValueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::Currency => write!(f, "currency"),
            Self::Date => write!(f, "date"),
            Self::Number => write!(f, "number"),
            Self::Email => write!(f, "email"),
        }
    }
}

/// Canonicalize a string value per SDP-1 rules.
pub fn canonicalize_string(s: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    // 1. Unicode NFC normalization
    let nfc: String = s.nfc().collect();
    // 2. Trim whitespace
    let trimmed = nfc.trim();
    // 3. Collapse internal whitespace to single space
    let collapsed: String = trimmed
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ");
    // 4. Lowercase
    collapsed.to_lowercase()
}
