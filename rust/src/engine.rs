//! Safe Rust side of MishMail's OpenPGP engine (scope B): verify detached
//! and cleartext signatures, decrypt, and read keys. Stateless: every call
//! receives the certificates and secret keys it may use; the app stores them
//! (Keychain, encrypted database), not this crate.
//!
//! Everything cryptographic is rPGP's. What lives here is *policy*, which
//! rPGP leaves to the application: which algorithms and hashes are
//! accepted, which key in a certificate may have made a signature, whether
//! a certificate and a signature are valid at a given time, and size limits.
//! It is deliberately strict and simple; see `cert_state` and `candidates`.
//!
//! Nothing here logs. The process must not install a `log` logger: rPGP logs
//! packet details at debug level.

use std::io::{BufReader, Cursor, Read};
use std::time::{SystemTime, UNIX_EPOCH};

use pgp::composed::{
    ArmorOptions, CleartextSignedMessage, Deserializable, DetachedSignature, Edata, Esk, Message,
    PublicOrSecret, SignedPublicKey, SignedSecretKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::errors::Error as PgpError;
use pgp::packet::{PublicKey, PublicSubkey, Signature, SignatureType};
use pgp::types::{KeyDetails, Password, Tag, VerifyingKey};
use serde::Serialize;
use zeroize::Zeroizing;

/// Largest input accepted (a message, a signature or a key file). Gmail's
/// limit for a whole message is 25 MB of attachments, about 35 MB encoded.
pub const MAX_INPUT: usize = 48 * 1024 * 1024;
/// Largest plaintext released by `decrypt`, after decompression. A
/// compression bomb stops here instead of exhausting memory.
pub const MAX_PLAINTEXT: u64 = 64 * 1024 * 1024;
/// Signatures checked per message, and session-key packets per message.
pub const MAX_SIGNATURES: usize = 16;
pub const MAX_SESSION_KEYS: usize = 32;
/// Tolerated clock difference for a signature created "in the future".
pub const CLOCK_SKEW_SECS: u64 = 600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineError {
    Malformed,
    NoSecretKey,
    PassphraseRequired,
    /// Encrypted without an integrity check (legacy SED), or the check
    /// (MDC or AEAD tag) failed: no plaintext is released.
    NotIntegrityProtected,
    TooLarge,
    Unsupported,
    Internal,
}

/// A certificate's standing at the time of the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Validity {
    Valid,
    Expired,
    Revoked,
    /// A self-signature does not verify, uses a rejected hash, or no user
    /// ID is bound: nothing in it can be trusted.
    Broken,
    /// An algorithm this engine refuses (Ed448, X448: rPGP implements them
    /// with the unaudited `cx448` crate).
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeySummary {
    pub fingerprint: String,
    pub user_ids: Vec<String>,
    pub has_secret: bool,
    pub created: u64,
    pub expires: Option<u64>,
    pub validity: Validity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SignatureResult {
    Good { signer: KeySummary },
    Bad,
    UnknownKey { key_id: String },
    /// Good maths, but the key is expired or revoked, the signing subkey is
    /// expired or revoked, or the signature itself has expired.
    KeyNotValid { signer: KeySummary },
    /// A rejected hash (MD5, RIPEMD-160, SHA-1) or algorithm (Ed448).
    Unsupported,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Decryption {
    /// True on every success; failures are errors, never `false`.
    pub integrity_protected: bool,
    pub signatures: Vec<SignatureResult>,
    #[serde(skip)]
    pub plaintext: Zeroizing<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Cleartext {
    pub signatures: Vec<SignatureResult>,
    #[serde(skip)]
    pub signed_text: Vec<u8>,
}

/// Keys accepted for storage, re-serialized by rPGP: only what was parsed
/// and checked is kept, never the bytes the user handed in.
pub struct Import {
    pub keys: Vec<KeySummary>,
    pub armored: Zeroizing<Vec<u8>>,
}

fn now_secs(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The caller's clock, refusing a missing or absurd one (fail closed).
pub fn system_time(unix_secs: i64) -> Result<SystemTime, EngineError> {
    if unix_secs <= 0 {
        return Err(EngineError::Internal);
    }
    Ok(UNIX_EPOCH + std::time::Duration::from_secs(unix_secs as u64))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn check_size(data: &[u8]) -> Result<(), EngineError> {
    if data.len() > MAX_INPUT {
        Err(EngineError::TooLarge)
    } else {
        Ok(())
    }
}

fn looks_armored(data: &[u8]) -> bool {
    let start = data.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(data.len());
    data[start..].starts_with(b"-----BEGIN ")
}

fn secs(t: pgp::types::Timestamp) -> u64 {
    u64::from(t.as_secs())
}

/// Data signatures: MD5, RIPEMD-160 and SHA-1 are refused (practical or
/// near-practical collisions). Self-signatures and bindings: MD5 and
/// RIPEMD-160 are refused, SHA-1 is accepted, because many long-lived keys
/// still carry SHA-1 self-signatures and rPGP checks them with
/// collision-detecting SHA-1 (`sha1-checked`).
fn data_hash_ok(sig: &Signature) -> bool {
    !matches!(sig.hash_alg(), None | Some(HashAlgorithm::Md5 | HashAlgorithm::Ripemd160 | HashAlgorithm::Sha1))
}

fn self_hash_ok(sig: &Signature) -> bool {
    !matches!(sig.hash_alg(), None | Some(HashAlgorithm::Md5 | HashAlgorithm::Ripemd160))
}

fn refused_algorithm(alg: PublicKeyAlgorithm) -> bool {
    matches!(alg, PublicKeyAlgorithm::Ed448 | PublicKeyAlgorithm::X448)
}

// MARK: - Keys

/// Every certificate and secret key in `data` (armored or binary, any
/// number of blocks). Unparseable data is an error; an empty input is none.
pub fn read_keys(data: &[u8]) -> Result<(Vec<SignedPublicKey>, Vec<SignedSecretKey>), EngineError> {
    check_size(data)?;
    let mut public = Vec::new();
    let mut secret = Vec::new();
    if data.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok((public, secret));
    }
    if looks_armored(data) {
        // Several armored blocks may follow one another. Armor headers such
        // as `Comment:` may be Latin-1; only the base64 lines matter, so the
        // text is read lossily.
        let text = String::from_utf8_lossy(data);
        for block in split_armor_blocks(&text) {
            let (keys, _) = PublicOrSecret::from_armor_many(Cursor::new(block.as_bytes()))
                .map_err(|_| EngineError::Malformed)?;
            for key in keys {
                push_key(key.map_err(|_| EngineError::Malformed)?, &mut public, &mut secret);
            }
        }
    } else {
        let (keys, _) = PublicOrSecret::from_reader_many(Cursor::new(data))
            .map_err(|_| EngineError::Malformed)?;
        for key in keys {
            push_key(key.map_err(|_| EngineError::Malformed)?, &mut public, &mut secret);
        }
    }
    Ok((public, secret))
}

fn push_key(key: PublicOrSecret, public: &mut Vec<SignedPublicKey>, secret: &mut Vec<SignedSecretKey>) {
    match key {
        PublicOrSecret::Public(k) => public.push(k),
        PublicOrSecret::Secret(k) => secret.push(k),
    }
}

fn split_armor_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim_end();
        if trimmed.starts_with("-----BEGIN PGP ") {
            current = Some(String::new());
        }
        if let Some(block) = current.as_mut() {
            block.push_str(trimmed);
            block.push('\n');
        }
        if trimmed.starts_with("-----END PGP ") {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
        }
    }
    blocks
}

/// What the keys in `data` are. Nothing is stored.
pub fn inspect_keys(data: &[u8], now: SystemTime) -> Result<Vec<KeySummary>, EngineError> {
    let (public, secret) = read_keys(data)?;
    if public.is_empty() && secret.is_empty() {
        return Err(EngineError::Malformed);
    }
    let mut out: Vec<KeySummary> = public.iter().map(|k| Cert::new(k).summary(false, now)).collect();
    out.extend(secret.iter().map(|k| Cert::new(&k.to_public_key()).summary(true, now)));
    Ok(out)
}

/// Public halves of every key in `data` that may be kept (not broken, not
/// an unsupported algorithm), re-serialized. Expired and revoked keys are
/// kept: they still say who signed an old message, and that the key is
/// revoked. Secret material is never part of the output.
pub fn import_public(data: &[u8], now: SystemTime) -> Result<Import, EngineError> {
    let (public, secret) = read_keys(data)?;
    let certs: Vec<SignedPublicKey> =
        public.into_iter().chain(secret.iter().map(|k| k.to_public_key())).collect();
    let mut keys = Vec::new();
    let mut armored = Zeroizing::new(Vec::new());
    for cert in &certs {
        let summary = Cert::new(cert).summary(false, now);
        if matches!(summary.validity, Validity::Broken | Validity::Unsupported) {
            continue;
        }
        armored.extend(cert.to_armored_bytes(ArmorOptions::default()).map_err(|_| EngineError::Internal)?);
        keys.push(summary);
    }
    if keys.is_empty() {
        return Err(EngineError::Malformed);
    }
    Ok(Import { keys, armored })
}

/// Secret keys in `data` that may be used to decrypt (valid, supported),
/// re-serialized, still protected by their own passphrase. A separate,
/// explicit action from importing public keys.
pub fn import_secret(data: &[u8], now: SystemTime) -> Result<Import, EngineError> {
    let (_, secret) = read_keys(data)?;
    let mut keys = Vec::new();
    let mut armored = Zeroizing::new(Vec::new());
    for key in &secret {
        let summary = Cert::new(&key.to_public_key()).summary(true, now);
        if summary.validity != Validity::Valid {
            continue;
        }
        armored.extend(key.to_armored_bytes(ArmorOptions::default()).map_err(|_| EngineError::Internal)?);
        keys.push(summary);
    }
    if keys.is_empty() {
        return Err(EngineError::NoSecretKey);
    }
    Ok(Import { keys, armored })
}

// MARK: - Certificate policy

/// True when `sig` names `key` as its issuer (fingerprint or key ID).
fn issued_by(sig: &Signature, key: &impl KeyDetails) -> bool {
    let fingerprint = key.fingerprint();
    let key_id = key.legacy_key_id();
    sig.issuer_fingerprint().iter().any(|f| f.as_bytes() == fingerprint.as_bytes())
        || sig.issuer_key_id().iter().any(|k| k.as_ref() == key_id.as_ref())
}

fn created(sig: &Signature) -> u64 {
    sig.created().map(secs).unwrap_or(0)
}

/// A signing-capable key of a certificate, with its standing.
#[derive(Clone, Copy)]
enum SigningKey<'a> {
    Primary(&'a PublicKey),
    Subkey(&'a PublicSubkey),
}

impl<'a> SigningKey<'a> {
    fn as_dyn(self) -> &'a dyn VerifyingKey {
        match self {
            SigningKey::Primary(k) => k,
            SigningKey::Subkey(k) => k,
        }
    }

    fn verify(self, sig: &Signature, data: &[u8]) -> bool {
        match self {
            SigningKey::Primary(k) => sig.verify(k, data).is_ok(),
            SigningKey::Subkey(k) => sig.verify(k, data).is_ok(),
        }
    }

    fn created(self) -> u64 {
        match self {
            SigningKey::Primary(k) => secs(k.created_at()),
            SigningKey::Subkey(k) => secs(k.created_at()),
        }
    }

    fn algorithm(self) -> PublicKeyAlgorithm {
        match self {
            SigningKey::Primary(k) => k.algorithm(),
            SigningKey::Subkey(k) => k.algorithm(),
        }
    }
}

struct Candidate<'a> {
    key: SigningKey<'a>,
    /// Usable for data signatures now (flag present, not revoked, not expired).
    usable: bool,
}

/// A certificate with its self-signatures checked once.
struct Cert<'a> {
    cert: &'a SignedPublicKey,
    /// Bound user IDs and whether each is revoked by its owner.
    users: Vec<(&'a pgp::types::SignedUser, bool)>,
    validity: Validity,
    expires: Option<u64>,
    /// The primary key may sign data (sign flag in its newest self-signature).
    primary_signs: bool,
}

impl<'a> Cert<'a> {
    /// Strict certificate policy:
    /// - only self-signatures count (third-party certifications are ignored:
    ///   there is no web of trust, and rPGP's own `verify_bindings` rejects a
    ///   key that carries one); each must verify with an accepted hash, and
    ///   at least one user ID must be bound, else `Broken`;
    /// - a user ID revoked by its owner is not listed;
    /// - any key revocation that verifies against the primary key means
    ///   `Revoked`, whatever its issuer subpacket or reason;
    /// - expiry: the earliest among the newest self-signature of each bound
    ///   user ID and the newest direct-key signature, judged at `now`;
    /// - Ed448/X448 primary keys are `Unsupported`.
    fn new(cert: &'a SignedPublicKey) -> Self {
        let mut this = Cert { cert, users: Vec::new(), validity: Validity::Broken,
                              expires: None, primary_signs: false };
        if refused_algorithm(cert.primary_key.algorithm()) {
            this.validity = Validity::Unsupported;
            return this;
        }
        let primary = &cert.primary_key;
        let mut newest: Vec<&Signature> = Vec::new();
        for user in &cert.details.users {
            let mut bound: Option<&Signature> = None;
            let mut revoked = false;
            for sig in user.signatures.iter().filter(|s| issued_by(s, primary)) {
                if !self_hash_ok(sig)
                    || sig.verify_certification(primary, Tag::UserId, &user.id).is_err()
                {
                    return this;
                }
                if sig.typ() == Some(SignatureType::CertRevocation) {
                    revoked = true;
                } else if bound.is_none_or(|b| created(sig) > created(b)) {
                    bound = Some(sig);
                }
            }
            if let Some(binding) = bound {
                this.users.push((user, revoked));
                if !revoked {
                    newest.push(binding);
                }
            }
        }
        if this.users.is_empty() {
            return this;
        }
        let mut newest_direct: Option<&Signature> = None;
        for sig in cert.details.direct_signatures.iter().filter(|s| issued_by(s, primary)) {
            if !self_hash_ok(sig) || sig.verify_key(primary).is_err() {
                return this;
            }
            if newest_direct.is_none_or(|d| created(sig) > created(d)) {
                newest_direct = Some(sig);
            }
        }
        newest.extend(newest_direct);

        let key_created = secs(primary.created_at());
        this.expires = newest
            .iter()
            .filter_map(|s| s.key_expiration_time())
            .map(|d| u64::from(d.as_secs()))
            .filter(|d| *d != 0)
            .map(|d| key_created + d)
            .min();
        // The newest self-signature overall carries the current key flags.
        this.primary_signs = newest
            .iter()
            .max_by_key(|s| created(s))
            .is_some_and(|s| s.key_flags().sign());
        // Every revocation is tried against the primary key, whatever issuer
        // it names (an issuer subpacket is not authenticated).
        let revoked = cert.details.revocation_signatures.iter()
            .any(|s| self_hash_ok(s) && s.verify_key(primary).is_ok());
        this.validity = if revoked { Validity::Revoked } else { Validity::Valid };
        this
    }

    fn validity(&self, now: SystemTime) -> Validity {
        match (self.validity, self.expires) {
            (Validity::Valid, Some(at)) if now_secs(now) >= at => Validity::Expired,
            (v, _) => v,
        }
    }

    fn summary(&self, has_secret: bool, now: SystemTime) -> KeySummary {
        KeySummary {
            fingerprint: hex(self.cert.primary_key.fingerprint().as_bytes()),
            user_ids: self.users.iter()
                .filter(|(_, revoked)| !revoked)
                .filter_map(|(u, _)| u.id.as_str().map(str::to_owned))
                .collect(),
            has_secret,
            created: secs(self.cert.primary_key.created_at()),
            expires: self.expires,
            validity: self.validity(now),
        }
    }

    /// Keys that may have issued `sig` (by issuer subpacket), each with
    /// whether it may sign data now. A subkey may sign only if its newest
    /// verifying binding carries the sign flag, it has no verifying
    /// revocation, and that binding's expiry has not passed.
    fn candidates(&self, sig: &Signature, now: SystemTime) -> Vec<Candidate<'a>> {
        let primary = &self.cert.primary_key;
        let mut out = Vec::new();
        if issued_by(sig, primary) {
            out.push(Candidate { key: SigningKey::Primary(primary), usable: self.primary_signs });
        }
        for sub in &self.cert.public_subkeys {
            if !issued_by(sig, &sub.key) {
                continue;
            }
            let mut newest: Option<&Signature> = None;
            let mut revoked = false;
            for s in &sub.signatures {
                if !self_hash_ok(s) || s.verify_subkey_binding(primary, &sub.key).is_err() {
                    continue;
                }
                match s.typ() {
                    Some(SignatureType::SubkeyRevocation) => revoked = true,
                    Some(SignatureType::SubkeyBinding)
                        if newest.is_none_or(|n| created(s) > created(n)) => newest = Some(s),
                    _ => {}
                }
            }
            let Some(binding) = newest else { continue };
            let expired = binding
                .key_expiration_time()
                .map(|d| u64::from(d.as_secs()))
                .filter(|d| *d != 0)
                .is_some_and(|d| now_secs(now) >= secs(sub.key.created_at()) + d);
            let usable = binding.key_flags().sign() && !revoked && !expired;
            out.push(Candidate { key: SigningKey::Subkey(&sub.key), usable });
        }
        out
    }
}

// MARK: - Signatures

fn issuer_label(sig: &Signature) -> String {
    if let Some(f) = sig.issuer_fingerprint().first() {
        return hex(f.as_bytes());
    }
    sig.issuer_key_id().first().map(|k| hex(k.as_ref())).unwrap_or_default()
}

/// One signature against every certificate given.
///
/// Order of checks: hash, issuer, maths, then time and standing. A
/// signature that verifies is reported against the key's standing; one
/// created before its key existed or beyond the clock skew is `Bad`; an
/// expired signature, or one by an unusable key, is `KeyNotValid`.
fn check_signature(
    sig: &Signature,
    certs: &[Cert<'_>],
    now: SystemTime,
    verify: impl Fn(SigningKey<'_>) -> bool,
) -> SignatureResult {
    if !data_hash_ok(sig) {
        return SignatureResult::Unsupported;
    }
    let mut issuer_known = false;
    for cert in certs {
        let candidates = cert.candidates(sig, now);
        if candidates.is_empty() {
            continue;
        }
        issuer_known = true;
        let Some(candidate) = candidates.into_iter().find(|c| verify(c.key)) else { continue };
        if refused_algorithm(candidate.key.algorithm()) || cert.validity == Validity::Unsupported {
            return SignatureResult::Unsupported;
        }
        let made = created(sig);
        let now_s = now_secs(now);
        if made == 0 || made < candidate.key.created() || made > now_s + CLOCK_SKEW_SECS {
            return SignatureResult::Bad;
        }
        let signature_expired = sig
            .signature_expiration_time()
            .map(|d| u64::from(d.as_secs()))
            .filter(|d| *d != 0)
            .is_some_and(|d| now_s >= made + d);
        let summary = cert.summary(false, now);
        return match summary.validity {
            Validity::Broken => SignatureResult::Bad,
            Validity::Unsupported => SignatureResult::Unsupported,
            Validity::Valid if candidate.usable && !signature_expired => {
                SignatureResult::Good { signer: summary }
            }
            _ => SignatureResult::KeyNotValid { signer: summary },
        };
    }
    if issuer_known {
        SignatureResult::Bad
    } else {
        SignatureResult::UnknownKey { key_id: issuer_label(sig) }
    }
}

/// At most `MAX_SIGNATURES`, identical ones once.
fn capped<T: PartialEq>(items: Vec<T>) -> Result<Vec<T>, EngineError> {
    let mut out: Vec<T> = Vec::new();
    for item in items {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    if out.len() > MAX_SIGNATURES {
        return Err(EngineError::Malformed);
    }
    Ok(out)
}

fn parse_certs(certs: &[u8]) -> Result<Vec<SignedPublicKey>, EngineError> {
    let (public, secret) = read_keys(certs)?;
    Ok(public.into_iter().chain(secret.iter().map(|k| k.to_public_key())).collect())
}

/// A detached signature (`application/pgp-signature`) over `data`, which
/// for PGP/MIME is the canonical (CRLF) signed part.
pub fn verify_detached(
    data: &[u8],
    signature: &[u8],
    certs: &[u8],
    now: SystemTime,
) -> Result<Vec<SignatureResult>, EngineError> {
    check_size(data)?;
    check_size(signature)?;
    let certs = parse_certs(certs)?;
    let certs: Vec<Cert<'_>> = certs.iter().map(Cert::new).collect();
    let sigs: Vec<DetachedSignature> = if looks_armored(signature) {
        // Several armored blocks may follow one another.
        let text = String::from_utf8_lossy(signature);
        let mut all = Vec::new();
        for block in split_armor_blocks(&text).into_iter().take(MAX_SIGNATURES * 4) {
            let (iter, _) = DetachedSignature::from_armor_many(Cursor::new(block.into_bytes()))
                .map_err(|_| EngineError::Malformed)?;
            for sig in iter.take(MAX_SIGNATURES * 4) {
                all.push(sig.map_err(|_| EngineError::Malformed)?);
            }
        }
        all
    } else {
        DetachedSignature::from_bytes_many(BufReader::new(Cursor::new(signature)))
            .map_err(|_| EngineError::Malformed)?
            .take(MAX_SIGNATURES * 4)
            .collect::<Result<_, _>>()
            .map_err(|_| EngineError::Malformed)?
    };
    let sigs = capped(sigs)?;
    if sigs.is_empty() {
        return Err(EngineError::Malformed);
    }
    Ok(sigs
        .iter()
        .map(|d| check_signature(&d.signature, &certs, now, |key| key.verify(&d.signature, data)))
        .collect())
}

/// A cleartext-signed message. The signed text returned is rPGP's view of
/// it (dash-escaping undone, CRLF): the only text that may be shown as
/// signed.
pub fn verify_cleartext(message: &[u8], certs: &[u8], now: SystemTime) -> Result<Cleartext, EngineError> {
    check_size(message)?;
    let certs = parse_certs(certs)?;
    let certs: Vec<Cert<'_>> = certs.iter().map(Cert::new).collect();
    let (msg, _) = CleartextSignedMessage::from_armor(Cursor::new(message))
        .map_err(|_| EngineError::Malformed)?;
    let text = msg.signed_text();
    let sigs = capped(msg.signatures().to_vec())?;
    let signatures = sigs
        .iter()
        .map(|sig| check_signature(sig, &certs, now, |key| key.verify(sig, text.as_bytes())))
        .collect();
    Ok(Cleartext { signatures, signed_text: text.into_bytes() })
}

// MARK: - Decryption

/// Decrypts with any of `secret_keys` (unlocked with `passphrase`), then
/// verifies signatures inside against `certs` plus the secret keys' own
/// public halves.
pub fn decrypt(
    message: &[u8],
    secret_keys: &[u8],
    passphrase: &[u8],
    certs: &[u8],
    now: SystemTime,
) -> Result<Decryption, EngineError> {
    check_size(message)?;
    let (_, secrets) = read_keys(secret_keys)?;
    if secrets.is_empty() {
        return Err(EngineError::NoSecretKey);
    }
    let mut public = parse_certs(certs)?;
    public.extend(secrets.iter().map(|k| k.to_public_key()));
    let certs: Vec<Cert<'_>> = public.iter().map(Cert::new).collect();

    let source = BufReader::new(Cursor::new(message));
    let parsed = if looks_armored(message) {
        Message::from_armor(source).map(|(m, _)| m)
    } else {
        Message::from_bytes(source)
    }
    .map_err(|_| EngineError::Malformed)?;
    let addressed = recipients(&parsed, &secrets)?;

    let password = Password::from(passphrase);
    let passwords: Vec<&Password> = secrets.iter().map(|_| &password).collect();
    let mut decrypted = parsed
        .decrypt_with_keys(passwords, secrets.iter().collect())
        .map_err(|e| map_decrypt_error(e, addressed))?;
    // Compressed, or signed-then-compressed, possibly nested a few times.
    for _ in 0..4 {
        if !(decrypted.is_compressed() || decrypted.is_signed()) {
            break;
        }
        decrypted = decrypted.decompress().map_err(|_| EngineError::Malformed)?;
    }
    let mut plaintext = Zeroizing::new(Vec::new());
    // For SEIPD v1 rPGP checks the MDC before releasing plaintext; a failed
    // check surfaces as an error here or above, and nothing is returned.
    (&mut decrypted)
        .take(MAX_PLAINTEXT + 1)
        .read_to_end(&mut plaintext)
        .map_err(|e| if io_integrity_failure(&e) { EngineError::NotIntegrityProtected } else { EngineError::Malformed })?;
    if plaintext.len() as u64 > MAX_PLAINTEXT {
        return Err(EngineError::TooLarge);
    }

    let mut signatures = Vec::new();
    if let Message::Signed { reader, .. } = &decrypted {
        let count = reader.num_signatures();
        if count > MAX_SIGNATURES {
            return Err(EngineError::Malformed);
        }
        for index in 0..count {
            let Some(sig) = reader.signature(index).cloned() else { continue };
            signatures.push(check_signature(&sig, &certs, now, |key| {
                decrypted.verify_nested_explicit(index, key.as_dyn()).is_ok()
            }));
        }
    }
    Ok(Decryption { integrity_protected: true, signatures, plaintext })
}

/// Which of our keys the message is for, and whether such a key is
/// passphrase-protected. Refuses legacy SED (no integrity protection),
/// too many session-key packets, and recipients we would only reach through
/// an X448 key.
fn recipients(message: &Message<'_>, secrets: &[SignedSecretKey]) -> Result<Recipients, EngineError> {
    let Message::Encrypted { esk, edata, .. } = message else { return Err(EngineError::Malformed) };
    if matches!(edata, Edata::SymEncryptedData { .. }) {
        return Err(EngineError::NotIntegrityProtected);
    }
    if esk.len() > MAX_SESSION_KEYS {
        return Err(EngineError::Malformed);
    }
    let mut found = Recipients { addressed: false, locked: false, refused: false };
    for pkesk in esk.iter().filter_map(|e| match e {
        Esk::PublicKeyEncryptedSessionKey(p) => Some(p),
        Esk::SymKeyEncryptedSessionKey(_) => None,
    }) {
        for key in secrets {
            if pkesk.match_identity(&key.primary_key) {
                found.note(refused_algorithm(key.primary_key.algorithm()),
                           key.primary_key.secret_params().is_encrypted());
            }
            for sub in &key.secret_subkeys {
                if pkesk.match_identity(&sub.key) {
                    found.note(refused_algorithm(sub.key.algorithm()),
                               sub.key.secret_params().is_encrypted());
                }
            }
        }
    }
    if found.refused && !found.addressed {
        return Err(EngineError::Unsupported);
    }
    Ok(found)
}

#[derive(Clone, Copy)]
struct Recipients {
    /// One of our supported keys is a recipient.
    addressed: bool,
    /// Such a key is passphrase-protected.
    locked: bool,
    /// One of our keys is a recipient, but only through a refused algorithm.
    refused: bool,
}

impl Recipients {
    fn note(&mut self, refused: bool, locked: bool) {
        if refused {
            self.refused = true;
        } else {
            self.addressed = true;
            self.locked |= locked;
        }
    }
}

/// rPGP reports "no usable key" (including a wrong passphrase, which leaves
/// the key unusable) as `MissingKey`; which one it was follows from whether
/// a recipient key is ours and locked. A failed MDC or AEAD check is an
/// integrity failure.
fn map_decrypt_error(error: PgpError, found: Recipients) -> EngineError {
    if is_integrity_failure(&error) {
        return EngineError::NotIntegrityProtected;
    }
    match error {
        PgpError::MissingKey if !found.addressed => EngineError::NoSecretKey,
        PgpError::MissingKey if found.locked => EngineError::PassphraseRequired,
        PgpError::Unsupported { .. } | PgpError::Unimplemented { .. } => EngineError::Unsupported,
        _ => EngineError::Malformed,
    }
}

/// MDC and AEAD failures, also when rPGP wraps them in an I/O error (it
/// does when the check happens while reading the decrypted stream).
fn is_integrity_failure(error: &PgpError) -> bool {
    match error {
        PgpError::MdcError | PgpError::Aead { .. } => true,
        PgpError::IO { source, .. } => io_integrity_failure(source),
        _ => false,
    }
}

fn io_integrity_failure(error: &std::io::Error) -> bool {
    let Some(inner) = error.get_ref() else { return false };
    inner.downcast_ref::<PgpError>().is_some_and(is_integrity_failure)
        || inner.downcast_ref::<pgp::crypto::aead::Error>().is_some()
}
