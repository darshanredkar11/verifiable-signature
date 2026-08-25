//! C-ABI boundary for Java's Foreign Function & Memory API (java.lang.foreign, stable
//! since JDK 22). Every exported function takes null-terminated UTF-8 C strings in and
//! returns a heap-allocated null-terminated UTF-8 C string out — always valid JSON,
//! `{"error": "..."}` on failure so the caller has one shape to parse either way.
//!
//! Memory contract: any `*mut c_char` returned by an `sdp_*` function is owned by Rust
//! and MUST be released by passing it to `sdp_free_string`. Never free it with anything
//! else (libc free, a different allocator, etc.) — the allocation was made by Rust's
//! global allocator via `CString::into_raw`, and only `CString::from_raw` reclaims it
//! correctly.

use std::ffi::{c_char, CStr, CString};

use crate::api::{api_commit, api_generate_keypair, api_verify};

fn to_str<'a>(ptr: *const c_char) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err("null pointer passed across FFI boundary".to_string());
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|e| format!("invalid UTF-8 in FFI argument: {}", e))
}

fn ok_or_error_json(result: Result<String, String>) -> *mut c_char {
    let body = match result {
        Ok(json) => json,
        Err(msg) => serde_json::json!({ "error": msg }).to_string(),
    };
    CString::new(body)
        .unwrap_or_else(|_| CString::new("{\"error\":\"internal: NUL byte in response\"}").unwrap())
        .into_raw()
}

/// Generate a fresh Ed25519 keypair. Returns JSON: {"privateKeyHex": "...", "publicKeyHex": "..."}.
#[no_mangle]
pub extern "C" fn sdp_generate_keypair() -> *mut c_char {
    let line = api_generate_keypair();
    let mut parts = line.split(' ');
    let priv_hex = parts.next().unwrap_or("");
    let pub_hex = parts.next().unwrap_or("");
    let json = serde_json::json!({ "privateKeyHex": priv_hex, "publicKeyHex": pub_hex }).to_string();
    CString::new(json).unwrap().into_raw()
}

/// Commit a document. All four arguments are null-terminated UTF-8 JSON/hex C strings.
/// Returns a JSON commitment string (or `{"error": "..."}`) — caller must free with `sdp_free_string`.
#[no_mangle]
pub extern "C" fn sdp_commit(
    doc_json: *const c_char,
    schema_json: *const c_char,
    privkey_hex: *const c_char,
    schema_version: *const c_char,
) -> *mut c_char {
    let result = (|| {
        let doc = to_str(doc_json)?;
        let schema = to_str(schema_json)?;
        let privkey = to_str(privkey_hex)?;
        let version = to_str(schema_version)?;
        api_commit(doc, schema, privkey, version)
    })();
    ok_or_error_json(result)
}

/// Verify a current document representation against a signed original commitment.
/// Returns a JSON `SemanticDeltaProof` string (or `{"error": "..."}`) — caller must free with `sdp_free_string`.
#[no_mangle]
pub extern "C" fn sdp_verify(
    doc_json: *const c_char,
    schema_json: *const c_char,
    commitment_json: *const c_char,
) -> *mut c_char {
    let result = (|| {
        let doc = to_str(doc_json)?;
        let schema = to_str(schema_json)?;
        let commitment = to_str(commitment_json)?;
        api_verify(doc, schema, commitment)
    })();
    ok_or_error_json(result)
}

/// Release a string previously returned by any `sdp_*` function. Safe to call once per
/// returned pointer; calling it twice on the same pointer, or on a pointer not returned
/// by this library, is undefined behavior (standard C-ABI ownership rules).
#[no_mangle]
pub extern "C" fn sdp_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(ptr));
    }
}
