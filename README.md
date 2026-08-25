# SDP-1: Semantic Delta Proof Engine

A prototype for cryptographically verifiable semantic delta evidence between an originally committed/signed document and a later representation.

## Quick Start

### Rust Core (library)

```bash
cd sdp-engine
cargo test            # All 6 tests pass
cargo build --release # Builds libsdp_engine.{so,dylib} (linked by Java via FFI) + the sdp-engine CLI
```

### Java Spring Boot API

The Java API calls the Rust engine **in-process** via the JDK 22 Foreign Function & Memory API — no subprocess, no temp files. Requires JDK 22+ and a release build of `sdp-engine` present at `sdp-engine/target/release/`.

```bash
cd sdp-api
mvn spring-boot:run
```

API available at `http://localhost:8080/api/sdp`

### One command (recommended)

```bash
make run   # builds the Rust cdylib + the Java jar, starts the service, prints URLs
```

## Deploying (Render, single container)

The repo ships a multi-stage `Dockerfile` that compiles the Rust `cdylib` and the Java jar in one image — no separate build pipelines, one service, one push:

```bash
docker build -t sdp-engine .
docker run -p 8080:8080 sdp-engine
```

On [Render](https://render.com): connect this repo — `render.yaml` at the root is a Blueprint, so Render provisions the web service automatically from the Dockerfile. Push to the connected branch to deploy.

## Demo Commands

See SPEC.md for full specification. Key endpoints:

- `POST /api/sdp/commit` - Commit a document, produce semantic commitment
- `POST /api/sdp/verify-unchanged` - Verify document is unchanged
- `POST /api/sdp/verify-reformatted` - Verify reformatted/semantically equivalent doc
- `POST /api/sdp/verify-modified` - Verify document with critical change
- `POST /api/sdp/tamper-field` - Test format-only changes

## Example Documents

| File | Description |
|------|-------------|
| `examples/contract_original.json` | Original contract with rent: €1,500 |
| `examples/contract_reformatted.json` | Same content, different formatting (1500 EUR) |
| `examples/contract_modified.json` | Rent changed to €1,800 (CRITICAL_CHANGE) |
| `examples/contract_tampered.json` | Landlord changed (SEMANTIC_CHANGE) |

## Architecture

```
SDP-1 Prototype
├── sdp-engine/     # Rust library (deterministic core) — the sole trust boundary
│   - Merkle trees, canonicalization, claim extraction, Ed25519 signing
│   - Compiled as both a cdylib (linked by Java) and an rlib (CLI + `cargo test`)
│   - 6 unit tests passing, independently testable
├── sdp-api/        # Java Spring Boot REST API
│   - 5 endpoints for all demo commands
│   - Calls the Rust cdylib in-process via java.lang.foreign (JDK 22 FFM API) —
│     no subprocess, no temp files
├── Dockerfile      # Single multi-stage build: Rust cdylib + Java jar -> one container
├── render.yaml     # Render Blueprint for push-to-deploy
├── examples/       # Example documents for demo
└── SPEC.md         # Full specification
```

## Novelty Claim

**NOT a new cryptographic algorithm.** Merkle trees, hash functions, and digital signatures are well-established prior art.

**Our contribution is the SDP-1 protocol/system design** combining:
- Deterministic claim extraction with schema-guided canonicalization
- Per-claim Merkle tree commitment (whole-document commitment only in prior art)
- Five-level change classification taxonomy
- Per-claim Merkle inclusion proofs for cryptographic evidence of exactly what changed
- Clear trusted/untrusted boundary definition
- Fail-closed security model

**Strongest actual contribution:** The protocol/system design X, where known primitives (Merkle trees, canonicalization, Ed25519 signatures) are combined in a new way for semantic delta evidence.

## Research Assessment

Key related work:

1. **W3C VC Data Integrity** - Canonicalizes and signs VCs, no semantic comparison between versions
2. **BBS Signatures / SD-JWT** - Selective disclosure from a single signed credential, not cross-document comparison
3. **WarrInt (USENIX Security 2026)** - Closest prior art. OCR-based comparison of legal documents. Key differences: no structured claims, no Merkle inclusion proofs per claim, no formal change classification, visual diff not cryptographic evidence
4. **C2PA** - Media provenance, not semantic delta
5. **Nika Spec** - Semantic identity hashing for workflows, not document semantics
6. **SourceScore citation chains** - Claim envelopes with subject/predicate/object, not cross-document delta

The SDP-1 protocol combines known primitives in a new configuration for a new problem: cryptographically verifiable semantic delta evidence.

## Security Model

**Trusted:** signing key, original commitment, canonicalization algorithm, claim schema
**Untrusted:** current document, extracted claims, parser output, metadata, user input

**12 attack scenarios** tested fail-closed (changes always detected one way or another).

## What We Are NOT Claiming

1. We are NOT claiming to have invented Merkle trees
2. We are NOT claiming to have invented canonicalization
3. We are NOT claiming semantic understanding of arbitrary PDFs (schema-guided only)
4. We are NOT claiming absolute semantic equivalence (depends on schema)
5. We are NOT claiming this replaces EUDI/W3C VC signatures (it's an additional layer)
6. We are NOT claiming patentability (individual primitives are prior art)
7. We are NOT claiming general-purpose document comparison (works with structured documents per schema)

## Priority Order (if time runs short)

- **P0**: Deterministic Rust core, commit, verify, semantic delta, Merkle proof, tests ✅
- **P1**: REST API, signed commitment, demo documents ✅
- **P2**: PDF adapter, EUDI integration mock, VP/selective disclosure adapter
- **P3**: UI

## Status

Prototype complete and presentation-ready for tomorrow. Built in ~8 hours from scratch.