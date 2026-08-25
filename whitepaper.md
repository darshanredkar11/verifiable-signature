# SDP-1: Semantic Delta Proof Engine
## A Cryptographic Protocol for Verifiable Semantic Delta Evidence Between Document Representations

**Document Version:** 1.0.0  
**Specification Reference:** SDP-1.0.0  
**Repository Layer:** `verifiable-signature` (`sdp-engine` & `sdp-api`)  
**Status:** Prototype Reference Implementation  

---

## Abstract

Traditional public key infrastructure (PKI) and digital signature standards (e.g., CAdES, XAdES, PAdES, W3C VC Data Integrity) bind cryptographic signatures to exact byte sequences. While byte-level integrity verification guarantees that a document has not suffered bitwise alteration, it introduces extreme fragility into digital workflows. Real-world document lifecycles routinely require harmless transformations—such as PDF/A archiving, optical character recognition (OCR), layout normalization, whitespace collapsing, or localized metadata updates. Under conventional signature validation, any byte-level variance forces a complete verification failure (`BYTE_INTEGRITY: FAIL`), rendering valid, legally unchanged documents untrusted. Conversely, a minor byte-level alteration can mask a severe, legally material modification (e.g., changing monthly rent from €1,500 to €1,800).

To bridge the gap between byte-level cryptographic integrity and semantic preservation, we present **SDP-1 (Semantic Delta Proof Engine)**. SDP-1 is a protocol and system architecture that produces cryptographically verifiable evidence of semantic change between an original, signed document commitment and any subsequent document instance. SDP-1 combines schema-guided claim extraction, deterministic canonicalization, per-claim Merkle tree commitments with domain-separated hashing, Ed25519 signature envelopes, a five-level change severity taxonomy, and per-claim Merkle inclusion proofs. We demonstrate a dual-engine reference implementation consisting of a high-performance, deterministic Rust core library (`sdp-engine`) and an enterprise Java Spring Boot REST API (`sdp-api`). Finally, we position SDP-1 as an evidence layer designed to operate on top of the EU Digital Identity (EUDI) Wallet and eIDAS 2.0 frameworks.

---

## 1. Introduction & Motivation

Digital signatures are fundamental to trust in modern electronic commerce, government services, and legal contracts. When an authority or individual signs a document using a Qualified Electronic Signature (QES), the signature algorithm (e.g., Ed25519, RSA-PSS, ECDSA) computes a cryptographic hash over the document's binary payload and encrypts/signs that hash using the signer's private key.

### 1.1 The Fragility of Byte-Level Verification

Consider a digital contract signed by a landlord and tenant. Over the lifecycle of this document, it may undergo several legitimate processing steps:
1. Conversion from native format to PDF/A for long-term archiving.
2. Compression or font embedding adjustments by a document management system (DMS).
3. Scanning and subsequent Optical Character Recognition (OCR) text extraction.
4. Re-formatting across different regional locales (e.g., expressing €1,500 as "1500 EUR" or dates as "01.09.2026" vs "2026-09-01").

When a traditional signature verifier evaluates these transformed representations, it computes $\text{SHA-256}(D_{\text{reformatted}})$. Because $D_{\text{orig}} \neq D_{\text{reformatted}}$ at the byte level, the verification engine outputs `INVALID`. The system cannot distinguish between a benign re-formatting operation and malicious document tampering.

```
+-----------------------------------------------------------------------------------+
|                            TRADITIONAL SIGNATURE MODEL                            |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Original Bytes  ======>  SHA-256  ======>  Sig Verification  ===>  PASS         |
|                                                                                   |
|  Reformatted Bytes ====>  SHA-256  ======>  Sig Verification  ===>  FAIL (Reject) |
|  (Legally Identical)                                                              |
|                                                                                   |
|  Tampered Bytes ====>     SHA-256  ======>  Sig Verification  ===>  FAIL (Reject) |
|  (Rent changed: €1500 -> €1800)                                                  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### 1.2 The Semantic Verification Requirement

What business and legal verifiers actually require is a mechanism that answers two distinct questions:
1. **Identity & Authenticity:** *Who signed the original commitment?* (Answered by PKI / EUDI QES).
2. **Semantic Integrity & Delta Evidence:** *Has the legally relevant meaning changed? If so, what exact fields were changed, by how much, and can that delta be cryptographically proven?* (Answered by SDP-1).

SDP-1 decouples semantic claim verification from byte-level representation while preserving cryptographic proof. By building per-claim Merkle inclusion proofs, SDP-1 allows any verifier to inspect delta evidence that demonstrates precisely which fields remained untouched, which underwent format-only changes, and which underwent critical semantic modifications.

```
+-----------------------------------------------------------------------------------+
|                                SDP-1 PROTOCOL MODEL                               |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Reformatted Doc ===> Claim Extraction ===> Canonicalization ===> Merkle Root     |
|                       & Schema Guidance      Pipeline C              Match        |
|                                                                                   |
|                       Result: BYTE_INTEGRITY: FAIL                                |
|                               SEMANTIC_INTEGRITY: PASS                            |
|                               CLASSIFICATION: SEMANTICALLY_EQUIVALENT             |
|                                                                                   |
|  Tampered Doc    ===> Claim Extraction ===> Canonicalization ===> Merkle Root     |
|                       & Schema Guidance      Pipeline C              Mismatch     |
|                                                                                   |
|                       Result: BYTE_INTEGRITY: FAIL                                |
|                               SEMANTIC_INTEGRITY: FAIL                            |
|                               CLASSIFICATION: CRITICAL_CHANGE                     |
|                               EVIDENCE: Rent modified (1500 EUR -> 1800 EUR)     |
|                                         + Dual Merkle Inclusion Proofs            |
+-----------------------------------------------------------------------------------+
```

---

## 2. Problem Formulation & Definitions

Let $D$ denote a document payload, and let $\mathcal{S}$ denote a schema definition comprising $n$ field specifications $\{s_1, s_2, \dots, s_n\}$.

### 2.1 Formal Definitions

1. **Claim Extraction Function ($\mathcal{E}$):** A deterministic function that maps a document $D$ and schema $\mathcal{S}$ into a set of semantic claim triples $C$:
   $$\mathcal{E}(D, \mathcal{S}) \to C = \{c_1, c_2, \dots, c_m\}$$
   where each claim $c_i$ is represented as a triple $\langle \text{subject}_i, \text{predicate}_i, \text{value}_i \rangle$.

2. **Canonicalization Pipeline ($\mathcal{C}$):** A deterministic mapping applied to claims that normalizes representations without altering legal semantics:
   $$\mathcal{C}(c_i) \to c_i' = \langle \text{nfc}(\text{subject}_i), \text{nfc}(\text{predicate}_i), \text{normalize}_{\text{type}}(\text{value}_i) \rangle$$
   where $\text{canonical\_key}(c_i') = \text{lowercase}(\text{subject}_i' \parallel \text{"|"} \parallel \text{predicate}_i' \parallel \text{"|"} \parallel \text{value}_i')$.

3. **Per-Claim Leaf Hashing ($\mathcal{H}_{\text{leaf}}$):** Domain-separated hashing of canonical claim keys:
   $$h_i = \text{SHA-256}(\text{canonical\_key}(c_i'))$$
   $$\text{leaf}_i = \mathcal{H}_{\text{leaf}}(h_i) = \text{SHA-256}(\text{"SDP:leaf:"} \parallel h_i)$$

4. **Internal Merkle Hashing ($\mathcal{H}_{\text{internal}}$):** Domain-separated hashing for internal Merkle tree nodes:
   $$\mathcal{H}_{\text{internal}}(L, R) = \text{SHA-256}(\text{"SDP:internal:"} \parallel L \parallel R)$$

5. **Semantic Commitment ($\mathcal{K}$):** Given a ordered sequence of leaf hashes $\langle \text{leaf}_1, \dots, \text{leaf}_m \rangle$ forming a Merkle tree $T$ with root $\mathcal{R}$, a semantic commitment $\mathcal{K}$ is defined as the tuple:
   $$\mathcal{K} = \langle \text{alg}, \text{commitment\_id}, \text{schema\_ver}, \mathcal{R}, m, \text{keys}, \sigma, pk, t_{\text{created}}, h_D \rangle$$
   where $\sigma = \text{Sign}_{sk}(\mathcal{R})$ is an Ed25519 digital signature over the 32-byte Merkle root $\mathcal{R}$, $pk$ is the corresponding Ed25519 public key, and $h_D = \text{SHA-256}(D_{\text{bytes}})$.

6. **Semantic Delta Proof ($\Delta$):** Given an original claim set $C_0$ (with commitment $\mathcal{K}_0$) and a current document $D_1$, the delta engine extracts $C_1$, builds Merkle tree $T_1$, and evaluates set differences and per-claim inclusion proofs:
   $$\Delta(C_0, T_0, \mathcal{K}_0, D_1, \mathcal{S}) \to \langle \text{status}, \text{byte\_integrity}, \text{semantic\_integrity}, \{\delta_j\}, \text{verification\_result} \rangle$$

---

## 3. SDP-1 Protocol Specification

The SDP-1 algorithm is specified under version identifier `sdp-1` (Algorithm Version `1.0.0`).

### 3.1 Schema Definition & Claim Extraction

Claims are extracted according to a pre-shared schema. The schema defines the target field path (supporting nested dot-notation), a human-readable display name, field criticality (`Normal` vs `Critical`), and value type (`Text`, `Currency`, `Date`, `Number`, `Email`).

```json
{
  "fieldName": "contract.rent",
  "displayName": "Monthly Rent",
  "criticality": "Critical",
  "valueType": "Currency"
}
```

Algorithm 1 specifies the claim extraction procedure:

```
Algorithm 1: Claim Extraction E(D, S)
Input : Document object D, Schema field list S
Output: Vector of extracted Claim triples C

1  C <- []
2  foreach field in S do
3      val <- TraversePath(D, field.fieldName)
4      if val != null then
5          norm_val <- NormalizeValue(val, field.valueType)
6          c <- Claim {
7              subject: field.fieldName,
8              predicate: "has_value",
9              value: norm_val
10         }
11         C.append(c)
12     end
13 end
14 Sort C lexicographically by c.canonical_key()
15 return C
```

### 3.2 Canonicalization Rules & Boundary Matrix

Canonicalization defines the boundary between transformations that are safe to silently normalize and those that represent semantic modifications.

```
+-----------------------------------------------------------------------------------+
|                             CANONICALIZATION MATRIX                               |
+-----------------------------------------------------------------------------------+
| Value Type  | Raw Input Example   | Canonical Normalized Form | Rule Applied      |
+-------------+---------------------+---------------------------+-------------------+
| Text        | "  Alice   SMITH "  | "alice smith"             | NFC, Trim,        |
|             |                     |                           | Collapse WS, Lower|
| Currency    | "€1,500"            | "1500.00 EUR"             | Symbol -> Code,   |
|             | "1500 EUR"          | "1500.00 EUR"             | 2-decimal format  |
| Date        | "01.09.2026"        | "2026-09-01"              | Parsed -> ISO 8601|
|             | "September 1, 2026" | "2026-09-01"              | Parsed -> ISO 8601|
| Number      | "1,500"             | "1500"                    | Stripped commas,  |
|             | "1500.00"           | "1500"                    | Integer coercion  |
+-----------------------------------------------------------------------------------+
```

#### Safe Normalizations (Applied Automatically)
1. **Unicode Normalization:** Unicode Normalization Form C (NFC) applied to all string buffers.
2. **Whitespace Normalization:** Leading/trailing whitespace trimmed; consecutive internal whitespace sequences collapsed to a single space $U+0020$.
3. **Case Folding:** Lowercasing applied where permitted by schema value type.
4. **Currency Normalization:** Standardizes symbols (`€`, `$`, `£`, `¥`) into ISO 4217 currency codes (`EUR`, `USD`, `GBP`, `JPY`) and formats numbers to two decimal places.
5. **Date Normalization:** Parses standard regional formats (`YYYY-MM-DD`, `DD/MM/YYYY`, `MM/DD/YYYY`, `DD.MM.YYYY`, `Month DD, YYYY`) into ISO 8601 extended format (`YYYY-MM-DD`).

#### Strict Non-Normalization Boundaries (Legal Semantics Preserved)
The protocol explicitly prohibits cross-unit or cross-currency normalization:
- **Currency Code Changes:** `1500 EUR` and `1500 USD` are treated as distinct values (`CRITICAL_CHANGE`).
- **Scale / Multipliers:** `1.5%` and `15%` must never be coerced to identical values.
- **Ambiguous Date Interpretations:** In the absence of schema locale context, `01/02/2026` must not silently guess between Feb 1st and Jan 2nd.

### 3.3 Domain-Separated Merkle Tree Construction

To prevent Merkle tree second-preimage attacks, SDP-1 enforces strict domain separation prefixes on leaf nodes and internal nodes.

```
               +-------------------------------------------+
               |            Merkle Root (R)                |
               +-------------------------------------------+
                                    / \
                                   /   \
   +---------------------------------+ +---------------------------------+
   | H_internal("SDP:internal:"|L|R) | | H_internal("SDP:internal:"|L|R) |
   +---------------------------------+ +---------------------------------+
              /             \                      /             \
            /                 \                  /                 \
   +---------------+   +---------------+   +---------------+   +---------------+
   | H_leaf(h_0)   |   | H_leaf(h_1)   |   | H_leaf(h_2)   |   | H_leaf(h_3)   |
   +---------------+   +---------------+   +---------------+   +---------------+
          |                   |                   |                   |
   h_0 = SHA256(c_0)   h_1 = SHA256(c_1)   h_2 = SHA256(c_2)   h_3 = SHA256(c_3)
```

1. **Leaf Pre-Hashing:** For claim $c_i \in C$, compute $h_i = \text{SHA-256}(\text{canonical\_key}(c_i))$.
2. **Leaf Node Hashing:** 
   $$\text{leaf}_i = \text{SHA-256}(\text{"SDP:leaf:"} \parallel h_i)$$
3. **Power-of-Two Padding:** If the leaf count $m$ is not a power of 2, the array is padded by duplicating the final leaf $\text{leaf}_m$ until $|T_{\text{leaves}}| = 2^{\lceil \log_2 m \rceil}$.
4. **Internal Node Hashing:** For sibling pair $(N_{2k}, N_{2k+1})$:
   $$N_{\text{parent}} = \text{SHA-256}(\text{"SDP:internal:"} \parallel N_{2k} \parallel N_{2k+1})$$

### 3.4 Commitment Generation & Ed25519 Signing

Once the Merkle root $\mathcal{R}$ is computed, the engine signs $\mathcal{R}$ using an Ed25519 private key:

```
Algorithm 2: Commit Document (D, S, sk)
Input : Document D, Schema S, Ed25519 Signing Key sk
Output: CommitResult { commitment, claims, tree }

1  C <- ExtractClaims(D, S)
2  Sort C lexicographically
3  leaf_hashes <- []
4  foreach c in C do
5      h_i <- SHA256(c.canonical_key())
6      leaf_hashes.append(SHA256("SDP:leaf:" || h_i))
7  end
8  tree <- MerkleTree::new(leaf_hashes)
9  R <- tree.root
10 sig <- Ed25519_Sign(sk, R)
11 commitment_id <- "sdp:" || hex(R[0..8]) || ":" || timestamp_str()
12 commitment <- SemanticCommitment {
13     algorithm: "sdp-1",
14     commitment_id: commitment_id,
15     schema_version: "1.0",
16     merkle_root: hex(R),
17     claim_count: C.length,
18     claim_keys: C.map(c => c.canonical_key()),
19     signature: hex(sig),
20     public_key: hex(sk.public_key()),
21     created_at: ISO8601_Now(),
22     document_hash: hex(SHA256(D))
23 }
24 return CommitResult { commitment, C, tree }
```

---

## 4. Semantic Change Taxonomy & Delta Engine

SDP-1 defines a strict 5-level change classification taxonomy to categorise the difference between document versions.

### 4.1 The 5-Level Severity Taxonomy

```
+------------------------------------------------------------------------------------+
|                       FIVE-LEVEL CHANGE SEVERITY TAXONOMY                          |
+----+-------------------------+-----------------------------------------------------+
| Lvl| Classification          | Operational & Legal Meaning                         |
+----+-------------------------+-----------------------------------------------------+
| 1  | UNCHANGED               | Bytes and semantic commitment are 100% identical.   |
| 2  | FORMAT_ONLY             | Byte hash differs, but raw claim strings match      |
|    |                         | after basic whitespace/casing normalization.        |
| 3  | SEMANTICALLY_EQUIVALENT | Byte hash differs; claim representations differ     |
|    |                         | (e.g., €1500 vs 1500 EUR), but type-aware           |
|    |                         | canonicalization maps them to identical values.     |
| 4  | SEMANTIC_CHANGE         | Non-critical claim modified, added, or removed      |
|    |                         | (e.g., contract description or optional meta data). |
| 5  | CRITICAL_CHANGE         | Critical claim modified, added, or removed          |
|    |                         | (e.g., rent €1500 -> €1800, landlord identity).     |
+----+-------------------------+-----------------------------------------------------+
```

### 4.2 Per-Claim Merkle Inclusion Proof Generation & Verification

When a claim $c_i$ is modified or tampered with, SDP-1 generates two cryptographic inclusion proofs:
1. $\pi_{\text{orig}}$: Proves that $c_{i, \text{orig}}$ was part of the original signed Merkle root $\mathcal{R}_0$.
2. $\pi_{\text{curr}}$: Proves that $c_{i, \text{curr}}$ is part of the current Merkle root $\mathcal{R}_1$.

A proof $\pi$ consists of an ordered sequence of sibling hashes and positions $(\text{Left} \mid \text{Right})$. Verification checks:

$$\text{VerifyProof}(\pi, \mathcal{R}) \iff \text{FoldHash}(\pi.\text{leaf\_hash}, \pi.\text{path}) == \mathcal{R}$$

```
Algorithm 3: Merkle Proof Verification
Input : MerkleInclusionProof proof, Expected Merkle Root R_expected
Output: Boolean (True if proof resolves to R_expected)

1  current <- hex_decode(proof.leaf_hash)
2  foreach step in proof.path do
3      sibling <- hex_decode(step.hash)
4      if step.position == Left then
5          current <- SHA256("SDP:internal:" || sibling || current)
6      else
7          current <- SHA256("SDP:internal:" || current || sibling)
8      end
9  end
10 return current == R_expected
```

---

## 5. System Architecture: Single Trust Boundary, In-Process Foreign Function Call

SDP-1 deliberately avoids a dual-implementation design. There is exactly **one** place where canonicalization, hashing, Merkle construction, signing, and classification happen: the `sdp-engine` Rust library, compiled as a C-ABI `cdylib`. The Java layer never re-derives a cryptographic result — it calls straight into the compiled Rust library **in-process**, via the JDK 22 Foreign Function & Memory API (`java.lang.foreign`, finalized by JEP 454, no JNI glue code and no `--enable-preview` flag required). There is no subprocess, no temp files, and no serialization to a filesystem in between — request and response are UTF-8 JSON strings passed directly across the FFI boundary, and the whole round trip (including a real Ed25519 signature and Merkle tree build) is sub-millisecond. This keeps the trust boundary auditable in one codebase instead of two implementations that could silently drift apart, and it deploys as a single container.

```
+-----------------------------------------------------------------------------------+
|                             SYSTEM ARCHITECTURE                                   |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [ Client Application / EUDI Wallet / Demo Console ]                              |
|                   |                                                               |
|                   v REST API (HTTP / JSON)                                        |
|  +-----------------------------------------------------------------------------+  |
|  | sdp-api (Java 22 / Spring Boot 3.3) — thin, non-cryptographic facade        |  |
|  | - SdpController.java: REST endpoints (/api/sdp/*), request/response         |  |
|  |   marshaling, fail-closed error propagation                                 |  |
|  | - RustEngine.java: java.lang.foreign downcall handles bound once at class   |  |
|  |   init to sdp_generate_keypair / sdp_commit / sdp_verify / sdp_free_string  |  |
|  +-----------------------------------------------------------------------------+  |
|                   |                                                               |
|                   v In-process FFI call (java.lang.foreign), UTF-8 JSON args      |
|  +-----------------------------------------------------------------------------+  |
|  | libsdp_engine.so — Rust cdylib, the sole trust boundary                     |  |
|  | - ffi.rs: #[no_mangle] extern "C" boundary — CString in, CString out,       |  |
|  |   sdp_free_string releases Rust-owned memory (explicit ownership contract)  |  |
|  | - api.rs: shared commit/verify logic, called identically by ffi.rs AND      |  |
|  |   by the CLI binary below — one implementation, two entry points           |  |
|  | - extract.rs / claim.rs: schema-guided extraction & canonicalization        |  |
|  | - merkle.rs: domain-separated binary Merkle tree & proof generator          |  |
|  | - commit.rs: Ed25519 signing & semantic commitment builder                  |  |
|  | - delta.rs: change classification taxonomy & evidence generator             |  |
|  | - src/bin/sdp-engine.rs: standalone CLI (generate-keypair/commit/verify),   |  |
|  |   for local testing and scripting — calls the same api.rs functions        |  |
|  +-----------------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

### 5.1 Rust Engine (`sdp-engine`)

The crate builds two artifacts from one source tree (`crate-type = ["cdylib", "rlib"]` in `Cargo.toml`): the shared library Java links against, and the `rlib` used by `cargo test` and the CLI binary. Key modules:
- `claim.rs`: Data models for `Claim`, `ClaimSchema`, `ClaimDelta`, `ChangeClassification`, `ValueType`; canonical-key vs. identity-key claim matching.
- `extract.rs`: Schema-guided field traversal and type normalizations (`normalize_currency`, `normalize_date`, `normalize_number`).
- `merkle.rs`: Merkle tree generation with `SDP:leaf:` and `SDP:internal:` domain-separation prefixes.
- `commit.rs`: Ed25519 keypair generation using `ed25519-dalek` and document commitment assembly.
- `delta.rs`: Delta engine computing byte integrity, semantic integrity, claim set differences, proof synthesis, and verification.
- `api.rs`: the single shared entry point (`api_commit`, `api_verify`, `api_generate_keypair`) called by both `ffi.rs` and the CLI — the two callers can never diverge because they run the same code.
- `ffi.rs`: the `#[no_mangle] extern "C"` boundary exposed to Java, with an explicit memory-ownership contract (`sdp_free_string`).

All 6 core unit tests in `sdp-engine` pass cleanly:
- `test_merkle_single_leaf`
- `test_merkle_two_leaves`
- `test_merkle_proof_roundtrip`
- `test_merkle_proof_invalid`
- `test_empty_tree`
- `test_commit_and_verify`

### 5.2 Java Spring Boot API (`sdp-api`)

The Java API exposes 5 HTTP REST endpoints. All five are named-scenario aliases over the same two real engine subcommands (`commit`, `verify`) — the classification returned is whatever the Rust engine actually computes for the given document pair, not a per-endpoint canned value:
1. `POST /api/sdp/commit`: Commits document to produce signed semantic commitment.
2. `POST /api/sdp/verify-unchanged`: Runs `verify`; expected to resolve to `UNCHANGED` for a byte-identical payload.
3. `POST /api/sdp/verify-reformatted`: Runs `verify`; expected to resolve to `SEMANTICALLY_EQUIVALENT` for a re-encoded payload.
4. `POST /api/sdp/verify-modified`: Runs `verify`; resolves to `CRITICAL_CHANGE` or `SEMANTIC_CHANGE` with per-claim Merkle inclusion proofs, depending on the actual field changed.
5. `POST /api/sdp/tamper-field`: Mutates one field of the original document (date/currency notation or a metadata marker) and runs `verify` on the result.

---

## 6. Threat Model & Fail-Closed Security Analysis

SDP-1 adopts a strict **fail-closed** security model.

### 6.1 Trust Boundary Definition

```
+-----------------------------------------------------------------------------------+
|                             TRUST BOUNDARY MATRIX                                 |
+------------------------------------+----------------------------------------------+
| TRUSTED COMPONENTS                 | UNTRUSTED COMPONENTS                         |
+------------------------------------+----------------------------------------------+
| - Ed25519 Private Signing Key      | - Current Document Payload (D_1)             |
| - Original Semantic Commitment (K0)| - Extracted Claims before verification        |
| - Pre-Shared Schema (S)            | - Parser / OCR / PDF extraction streams      |
| - Canonicalization Algorithm (C)   | - User Inputs & Query Parameters             |
| - Public Key Verification (pk)     | - Unverified Merkle Inclusion Proofs         |
+------------------------------------+----------------------------------------------+
```

### 6.2 Analysis of 12 Attack Scenarios

```
+------------------------------------------------------------------------------------+
|                         ATTACK VECTOR ANALYSIS MATRIX                              |
+---+----------------------------------+-----------------------+---------------------+
|#  | Attack Scenario                  | Detection Mechanism   | Security Outcome    |
+---+----------------------------------+-----------------------+---------------------+
|1  | Single byte tampering in raw doc | SHA-256 Hash check    | BYTE_INTEGRITY: FAIL|
|2  | Whitespace / Indentation edit    | Canonicalization      | FORMAT_ONLY (Pass)  |
|3  | Semantic value alteration (€1800)| Merkle Root Mismatch  | CRITICAL_CHANGE     |
|4  | Deletion of a claim              | Set difference C0/C1  | SEMANTIC_CHANGE     |
|5  | Insertion of arbitrary claim     | Set difference C0/C1  | SEMANTIC_CHANGE     |
|6  | Reordering claim keys in JSON    | Lexicographical Sort  | Root match (Pass)   |
|7  | Duplicate key injection          | Map deduplication     | Detected & Handled  |
|8  | Format tweak (1500 -> 1500.00)   | Value Normalizer      | FORMAT_ONLY (Pass)  |
|9  | Currency swap (€1500 -> $1500)   | Currency Normalizer   | CRITICAL_CHANGE     |
|10 | Date representation shift        | Date Normalizer       | FORMAT_ONLY (Pass)  |
|11 | Claim key order manipulation     | Deterministic Sorting | Fail-closed         |
|12 | False Merkle inclusion proof     | Root path check       | Proof rejected      |
+---+----------------------------------+-----------------------+---------------------+
```

---

## 7. Related Work & Comparative Analysis

SDP-1 builds upon established cryptographic primitives while introducing a unique protocol combination for document semantic delta evidence.

```
+---------------------------------------------------------------------------------------------------+
|                                  RELATED WORK COMPARISON MATRIX                                   |
+----------------------+--------------------+--------------------+--------------------+-------------+
| System / Standard    | Granularity        | Cross-Doc Delta    | Proof Mechanism    | Taxonomy    |
+----------------------+--------------------+--------------------+--------------------+-------------+
| W3C VC Data Integr.  | Credential-Level   | No                 | JCS / RDF Signature| No          |
| BBS+ / SD-JWT        | Per-Claim          | No (Selective Disc)| Pairing / HMAC     | No          |
| WarrInt (USENIX 2026)| Document Text      | Yes (Visual Diff)  | Barcode / OCR      | Informal    |
| C2PA                 | Asset Manifest     | No (Provenance)    | JWS / Merkle Tree  | No          |
| Nika Spec            | Workflow IR        | No                 | Graph Hashing      | No          |
| SDP-1 (Our Work)     | Per-Claim Triple   | YES (Cryptographic)| Per-Claim Merkle   | 5-Level     |
|                      |                    |                    | Inclusion Proofs   | Hierarchy   |
+----------------------+--------------------+--------------------+--------------------+-------------+
```

### Key Differentiators:
1. **W3C VC Data Integrity:** Canonicalizes credentials for signing, but cannot compare two distinct credential versions or measure semantic delta.
2. **BBS+ / SD-JWT:** Solves selective disclosure (revealing a subset of claims to a verifier), whereas SDP-1 solves cross-version semantic comparison.
3. **WarrInt (USENIX Security 2026):** Closest prior art. WarrInt performs OCR-based text comparisons on legal warrants. However, WarrInt lacks structured per-claim Merkle inclusion proofs, does not provide a formal 5-level change taxonomy, and relies on visual diffs rather than cryptographic evidence.

---

## 8. EUDI Wallet & eIDAS 2.0 Integration Architecture

Under modern European identity frameworks (eIDAS 2.0 / EUDI Wallet), users receive Verifiable Credentials (VCs) and sign documents using Qualified Electronic Signatures (QES). SDP-1 integrates directly into the EUDI architecture as an **evidence validation layer**.

```
+-----------------------------------------------------------------------------------+
|                        EUDI WALLET + SDP-1 INTEGRATION LAYER                      |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  +--------------------------------+       +------------------------------------+  |
|  | EUDI Wallet / eIDAS 2.0 Layer |       | SDP-1 Semantic Evidence Layer      |  |
|  | - Qualified Certificate (QCert)|       | - Schema-Guided Claim Extraction   |  |
|  | - Signer Identity Verification |   +   | - Per-Claim Merkle Tree Commitment |  |
|  | - Non-Repudiation (QES)        |       | - 5-Level Change Classification    |  |
|  | - Legal Effect of Signature    |       | - Cryptographic Delta Evidence     |  |
|  +--------------------------------+       +------------------------------------+  |
|                               |                              |                    |
|                               +--------------+---------------+                    |
|                                              |                                    |
|                                              v                                    |
|                      +-----------------------------------------------+            |
|                      | Combined Trust Result:                        |            |
|                      | 1. Signer Identity: VALID (Alice Smith, QES)  |            |
|                      | 2. Document Evolution: SEMANTICALLY_EQUIV    |            |
|                      | 3. Delta Evidence: 0 Critical Changes         |            |
|                      +-----------------------------------------------+            |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

In an enterprise workflow, EUDI establishes **who** signed the original document, while SDP-1 establishes **what** changed during subsequent document processing steps.

---

## 9. Empirical Evaluation & Test Vectors

We evaluate SDP-1 using standard contract test vectors located in `examples/`.

### 9.1 Test Vectors

1. `contract_original.json`:
   ```json
   {
     "tenant": "Alice",
     "landlord": "Bob",
     "rent": "€1,500",
     "deposit": "€3,000",
     "start": "2026-09-01",
     "end": "2026-08-31"
   }
   ```

2. `contract_reformatted.json`: Same content, reformatted currency and dates (`1500 EUR`, `01.09.2026`).
3. `contract_modified.json`: Rent changed to `€1,800` (`CRITICAL_CHANGE`).
4. `contract_tampered.json`: Landlord changed to `Charlie` (`SEMANTIC_CHANGE`).

### 9.2 API Execution Trace

#### Commit Request (`POST /api/sdp/commit`)
```json
{
  "document": { "tenant": "Alice", "landlord": "Bob", "rent": "€1,500", "deposit": "€3,000", "startDate": "2026-09-01" },
  "schema": [
    { "fieldName": "tenant", "displayName": "Tenant", "criticality": "normal", "valueType": "text" },
    { "fieldName": "landlord", "displayName": "Landlord", "criticality": "normal", "valueType": "text" },
    { "fieldName": "rent", "displayName": "Rent", "criticality": "critical", "valueType": "currency" },
    { "fieldName": "deposit", "displayName": "Deposit", "criticality": "normal", "valueType": "currency" },
    { "fieldName": "startDate", "displayName": "Start", "criticality": "normal", "valueType": "date" }
  ]
}
```

#### Commit Response (captured from a live run — real Ed25519 signature, real Merkle root)
```json
{
  "status": "COMMITTED",
  "commitment": {
    "algorithm": "sdp-1",
    "commitmentId": "sdp:9f753dde3d5c9fad:20260825115628",
    "merkleRoot": "9f753dde3d5c9fada065431dfd5e87fe813500977ff1a3b4b1a9662bef77ea22",
    "claimCount": 5,
    "signature": "92f99d147b14f029cd427e90b9c6d4f2...(64 bytes)",
    "publicKey": "b41dcffcf8da1446c34755a79b2664ea408c6eb88a3835728223e0ccea7918f5",
    "documentHash": "393bea259875f1e24679477e48208f96dc8fa2988d685a50474f9b38dc7f7207"
  }
}
```

#### Verify Modified Response (`POST /api/sdp/verify-modified`, rent €1,500 → €1,800 — captured from a live run)
```json
{
  "byteIntegrity": "FAIL",
  "semanticIntegrity": "FAIL",
  "classification": "CRITICAL_CHANGE",
  "result": "CRITICAL_CHANGE",
  "changes": [
    {
      "claim": { "subject": "rent", "predicate": "has_value", "value": "rent" },
      "originalValue": "1500.00 EUR",
      "currentValue": "1800.00 EUR",
      "changeType": "MODIFIED",
      "classification": "CRITICAL_CHANGE",
      "originalMerkleProof": { "leafHash": "...", "leafIndex": 2, "path": [ /* 3 sibling hashes */ ], "root": "...", "treeSize": 5 },
      "currentMerkleProof": { "leafHash": "...", "leafIndex": 2, "path": [ /* 3 sibling hashes */ ], "root": "...", "treeSize": 5 }
    }
  ]
}
```

#### Verify Reformatted Response (`POST /api/sdp/verify-reformatted`, PDF/A-style re-encoding — captured from a live run)
```json
{
  "byteIntegrity": "FAIL",
  "semanticIntegrity": "PASS",
  "classification": "SEMANTICALLY_EQUIVALENT",
  "result": "SEMANTICALLY_EQUIVALENT",
  "changes": []
}
```

---

## 10. Novelty Claims & Protocol Boundaries

To ensure scientific clarity, we explicitly state what SDP-1 claims and what it does **not** claim.

### 10.1 Novelty Claims
- **Protocol & System Design Contribution:** Combining schema-guided claim extraction, type-aware canonicalization, per-claim Merkle commitments, Ed25519 signing, and a 5-level change taxonomy into a unified evidence protocol.
- **Per-Claim Merkle Proof Evidence:** Generating cryptographic inclusion proofs for both original and current values of individual modified claims.

### 10.2 What SDP-1 Does NOT Claim
1. **NOT a new cryptographic algorithm:** Merkle trees (1979), SHA-256, and Ed25519 are existing primitives.
2. **NOT general-purpose AI document comparison:** Extraction is schema-guided and deterministic; we do not use non-deterministic LLMs for claim verification.
3. **NOT absolute semantic equivalence:** Equivalence is defined relative to the provided schema and canonicalization rules.
4. **NOT a replacement for PKI / EUDI:** SDP-1 operates as an additional evidence layer on top of underlying electronic signature infrastructures.

---

## 11. Future Roadmap & Conclusion

### 11.1 Future Extensions
- **Zero-Knowledge Semantic Delta Proofs (zk-SNARKs):** Generating proofs that a document underwent only `FORMAT_ONLY` changes without revealing the underlying claim values to the verifier.
- **Native PDF Stream Adapters:** Embedding SDP-1 commitments directly into PDF Metadata / DSS (Document Security Store) structures.

### 11.2 Conclusion

SDP-1 provides a practical, cryptographically sound solution to the fragility of byte-level document signatures. By representing semantic content as canonical claim triples committed in domain-separated Merkle trees, SDP-1 produces verifiable evidence of document evolution. The reference implementation (`sdp-engine` and `sdp-api`) demonstrates that verifiable semantic delta evidence can be generated and verified efficiently in real-world document workflows.
