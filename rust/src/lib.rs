//! C ABI for DreaMail's OpenPGP engine (`OpenPGPEngine` in Swift).
//!
//! Every function takes byte buffers, returns an `DMResult` that the caller
//! frees with `dm_pgp_free`, and never panics across the boundary (a panic
//! is caught, reported as `internal`, and not printed). The JSON metadata
//! carries no message text and no key material; plaintext, signed text and
//! re-serialized keys travel in `data` only, which is zeroed when freed.
//! Nothing is logged and nothing is kept between calls.
//!
//! Scope B (owner's decision): verify, decrypt, read and import keys.
//! Nothing here signs or encrypts.
//!
//! `now_unix` is the caller's clock in seconds; zero or negative is refused
//! (`internal`) rather than read as 1970, which would make every expired key
//! look valid.

pub mod engine;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Once;

use engine::EngineError;
use serde_json::json;
use zeroize::Zeroize;

/// A buffer owned by this library. `ptr` is null when `len` is 0.
#[repr(C)]
pub struct DMBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

/// `json` is UTF-8: `{"ok":true,...}` or `{"ok":false,"error":"..."}`.
#[repr(C)]
pub struct DMResult {
    pub json: DMBuffer,
    pub data: DMBuffer,
}

impl DMBuffer {
    fn empty() -> Self {
        DMBuffer { ptr: std::ptr::null_mut(), len: 0 }
    }

    /// Takes the bytes into a buffer of exactly their length, so that
    /// freeing can rebuild the allocation. The source is zeroed.
    fn from_bytes(bytes: &mut Vec<u8>) -> Self {
        if bytes.is_empty() {
            return Self::empty();
        }
        let boxed: Box<[u8]> = bytes.as_slice().into();
        bytes.zeroize();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed) as *mut u8;
        DMBuffer { ptr, len }
    }

    /// Zeroes, then frees.
    unsafe fn free(self) {
        if self.ptr.is_null() {
            return;
        }
        let slice = std::ptr::slice_from_raw_parts_mut(self.ptr, self.len);
        let mut boxed = Box::from_raw(slice);
        boxed.zeroize();
        drop(boxed);
    }
}

fn ok(json: serde_json::Value, mut data: Vec<u8>) -> DMResult {
    let mut text = json.to_string().into_bytes();
    DMResult { json: DMBuffer::from_bytes(&mut text), data: DMBuffer::from_bytes(&mut data) }
}

fn err(error: EngineError) -> DMResult {
    ok(json!({ "ok": false, "error": error }), Vec::new())
}

/// # Safety
/// `ptr` must be valid for `len` bytes, or `len` must be 0.
unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len)
    }
}

/// Runs `f`, turning a panic into `internal`. The default panic hook would
/// print the panic message (which can quote input) to stderr: it is
/// replaced, once, by one that prints nothing.
fn guarded(f: impl FnOnce() -> DMResult) -> DMResult {
    static QUIET: Once = Once::new();
    QUIET.call_once(|| std::panic::set_hook(Box::new(|_| {})));
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| err(EngineError::Internal))
}

/// Runs `f` with the caller's clock, refusing an invalid one.
fn with_clock(now_unix: i64, f: impl FnOnce(std::time::SystemTime) -> DMResult) -> DMResult {
    match engine::system_time(now_unix) {
        Ok(now) => guarded(|| f(now)),
        Err(e) => err(e),
    }
}

/// # Safety
/// Each pointer must be valid for its length (or the length 0).
#[no_mangle]
pub unsafe extern "C" fn dm_pgp_verify_detached(
    data: *const u8,
    data_len: usize,
    signature: *const u8,
    signature_len: usize,
    certs: *const u8,
    certs_len: usize,
    now_unix: i64,
) -> DMResult {
    let (data, signature, certs) =
        (bytes(data, data_len), bytes(signature, signature_len), bytes(certs, certs_len));
    with_clock(now_unix, |now| match engine::verify_detached(data, signature, certs, now) {
        Ok(sigs) => ok(json!({ "ok": true, "signatures": sigs }), Vec::new()),
        Err(e) => err(e),
    })
}

/// # Safety
/// Each pointer must be valid for its length (or the length 0).
#[no_mangle]
pub unsafe extern "C" fn dm_pgp_verify_cleartext(
    message: *const u8,
    message_len: usize,
    certs: *const u8,
    certs_len: usize,
    now_unix: i64,
) -> DMResult {
    let (message, certs) = (bytes(message, message_len), bytes(certs, certs_len));
    with_clock(now_unix, |now| match engine::verify_cleartext(message, certs, now) {
        Ok(c) => ok(json!({ "ok": true, "signatures": c.signatures }), c.signed_text),
        Err(e) => err(e),
    })
}

/// # Safety
/// Each pointer must be valid for its length (or the length 0).
#[no_mangle]
pub unsafe extern "C" fn dm_pgp_decrypt(
    message: *const u8,
    message_len: usize,
    secret_keys: *const u8,
    secret_keys_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    certs: *const u8,
    certs_len: usize,
    now_unix: i64,
) -> DMResult {
    let message = bytes(message, message_len);
    let secret_keys = bytes(secret_keys, secret_keys_len);
    let passphrase = bytes(passphrase, passphrase_len);
    let certs = bytes(certs, certs_len);
    with_clock(now_unix, |now| {
        match engine::decrypt(message, secret_keys, passphrase, certs, now) {
            Ok(d) => ok(
                json!({ "ok": true, "integrity_protected": d.integrity_protected,
                        "signatures": d.signatures }),
                d.plaintext.to_vec(),
            ),
            Err(e) => err(e),
        }
    })
}

/// What the keys are, with their validity. Nothing is returned in `data`.
///
/// # Safety
/// `data` must be valid for `data_len` bytes (or the length 0).
#[no_mangle]
pub unsafe extern "C" fn dm_pgp_inspect_keys(data: *const u8, data_len: usize, now_unix: i64) -> DMResult {
    let data = bytes(data, data_len);
    with_clock(now_unix, |now| match engine::inspect_keys(data, now) {
        Ok(keys) => ok(json!({ "ok": true, "keys": keys }), Vec::new()),
        Err(e) => err(e),
    })
}

/// The public keys that may be stored, re-serialized in `data` (armored);
/// broken and unsupported keys are left out, secret material always.
///
/// # Safety
/// `data` must be valid for `data_len` bytes (or the length 0).
#[no_mangle]
pub unsafe extern "C" fn dm_pgp_import_public(data: *const u8, data_len: usize, now_unix: i64) -> DMResult {
    let data = bytes(data, data_len);
    with_clock(now_unix, |now| match engine::import_public(data, now) {
        Ok(import) => ok(json!({ "ok": true, "keys": import.keys }), import.armored.to_vec()),
        Err(e) => err(e),
    })
}

/// The secret keys that may be used (valid, supported), re-serialized in
/// `data` (armored, still under their own passphrase).
///
/// # Safety
/// `data` must be valid for `data_len` bytes (or the length 0).
#[no_mangle]
pub unsafe extern "C" fn dm_pgp_import_secret(data: *const u8, data_len: usize, now_unix: i64) -> DMResult {
    let data = bytes(data, data_len);
    with_clock(now_unix, |now| match engine::import_secret(data, now) {
        Ok(import) => ok(json!({ "ok": true, "keys": import.keys }), import.armored.to_vec()),
        Err(e) => err(e),
    })
}

/// Zeroes and frees both buffers of a result.
///
/// # Safety
/// `result` must come from this library and be freed once.
#[no_mangle]
pub unsafe extern "C" fn dm_pgp_free(result: DMResult) {
    result.json.free();
    result.data.free();
}
