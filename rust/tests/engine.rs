//! Round trips through rPGP with keys generated at test time. No key
//! material is stored in the repository.

use std::time::{Duration, SystemTime};

use mishmail_rpgp::engine::{self, EngineError, SignatureResult, Validity};
use pgp::composed::{
    ArmorOptions, CleartextSignedMessage, DetachedSignature, EncryptionCaps, KeyType,
    MessageBuilder, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::{ecc_curve::ECCCurve, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::types::{CompressionAlgorithm, KeyDetails, Password, Tag, Timestamp};
use rand::thread_rng;
use smallvec::smallvec;

// MARK: - Helpers

struct Spec<'a> {
    uid: &'a str,
    more_uids: &'a [&'a str],
    passphrase: Option<&'a str>,
    primary: KeyType,
    primary_signs: bool,
    signing_subkey: bool,
    encryption: KeyType,
    hash: HashAlgorithm,
}

impl Default for Spec<'_> {
    fn default() -> Self {
        Spec { uid: "Alice <alice@example.org>", more_uids: &[], passphrase: None,
               primary: KeyType::Ed25519Legacy, primary_signs: true, signing_subkey: false,
               encryption: KeyType::ECDH(ECCCurve::Curve25519Legacy), hash: HashAlgorithm::Sha256 }
    }
}

fn make(spec: Spec<'_>) -> SignedSecretKey {
    let mut subkeys = vec![SubkeyParamsBuilder::default()
        .key_type(spec.encryption)
        .passphrase(spec.passphrase.map(str::to_owned))
        .can_encrypt(EncryptionCaps::All)
        .build()
        .unwrap()];
    if spec.signing_subkey {
        subkeys.push(SubkeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .passphrase(spec.passphrase.map(str::to_owned))
            .can_sign(true)
            .build()
            .unwrap());
    }
    let mut params = SecretKeyParamsBuilder::default();
    params
        .key_type(spec.primary)
        .can_certify(true)
        .can_sign(spec.primary_signs)
        .primary_user_id(spec.uid.into())
        .user_ids(spec.more_uids.iter().map(|s| (*s).to_owned()).collect())
        .passphrase(spec.passphrase.map(str::to_owned))
        .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
        .preferred_hash_algorithms(smallvec![spec.hash])
        .preferred_compression_algorithms(smallvec![])
        .subkeys(subkeys);
    params.build().unwrap().generate(thread_rng()).unwrap()
}

fn generate(uid: &str, passphrase: Option<&str>) -> SignedSecretKey {
    make(Spec { uid, passphrase, ..Default::default() })
}

fn armor_public(cert: &SignedPublicKey) -> Vec<u8> {
    cert.to_armored_bytes(ArmorOptions::default()).unwrap()
}

fn public_armor(key: &SignedSecretKey) -> Vec<u8> {
    armor_public(&key.to_public_key())
}

fn secret_armor(key: &SignedSecretKey) -> Vec<u8> {
    key.to_armored_bytes(ArmorOptions::default()).unwrap()
}

fn armor_sig(sig: pgp::packet::Signature) -> Vec<u8> {
    DetachedSignature::new(sig).to_armored_bytes(ArmorOptions::default()).unwrap()
}

fn detached(key: &SignedSecretKey, pw: &str, data: &[u8]) -> Vec<u8> {
    detached_with(key, pw, data, HashAlgorithm::Sha256)
}

fn detached_with(key: &SignedSecretKey, pw: &str, data: &[u8], hash: HashAlgorithm) -> Vec<u8> {
    DetachedSignature::sign_binary_data(thread_rng(), &key.primary_key, &Password::from(pw),
                                        hash, data)
        .unwrap()
        .to_armored_bytes(ArmorOptions::default())
        .unwrap()
}

fn now() -> SystemTime {
    SystemTime::now()
}

fn later(days: u64) -> SystemTime {
    SystemTime::now() + Duration::from_secs(days * 86_400)
}

fn ts(offset_secs: i64) -> Timestamp {
    let base = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;
    Timestamp::from_secs((base + offset_secs) as u32)
}

/// `config` with its creation time (and expiries) replaced, plus `extra`.
fn retimed(config: &SignatureConfig, created: Timestamp, extra: Vec<SubpacketData>) -> SignatureConfig {
    let mut c = config.clone();
    c.hashed_subpackets.retain(|sp| !matches!(sp.data,
        SubpacketData::SignatureCreationTime(_) | SubpacketData::KeyExpirationTime(_)
        | SubpacketData::SignatureExpirationTime(_)));
    c.hashed_subpackets.insert(0, Subpacket::regular(SubpacketData::SignatureCreationTime(created)).unwrap());
    for data in extra {
        c.hashed_subpackets.push(Subpacket::regular(data).unwrap());
    }
    c
}

fn days(n: u32) -> pgp::types::Duration {
    pgp::types::Duration::from_secs(n * 86_400)
}

fn good_signer(result: &[SignatureResult]) -> bool {
    matches!(result, [SignatureResult::Good { .. }])
}

fn key_not_valid(result: &[SignatureResult]) -> bool {
    matches!(result, [SignatureResult::KeyNotValid { .. }])
}

// MARK: - Keys

#[test]
fn inspect_reports_fingerprint_user_ids_secrecy_and_validity() {
    let alice = generate("Alice <alice@example.org>", None);
    let keys = engine::inspect_keys(&public_armor(&alice), now()).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].user_ids, vec!["Alice <alice@example.org>".to_owned()]);
    assert!(!keys[0].has_secret);
    assert_eq!(keys[0].validity, Validity::Valid);
    assert_eq!(keys[0].expires, None);
    assert_eq!(keys[0].fingerprint.len(), 40);

    let both = [public_armor(&generate("Bob <bob@example.net>", None)), secret_armor(&alice)].concat();
    let keys = engine::inspect_keys(&both, now()).unwrap();
    assert_eq!(keys.iter().filter(|k| k.has_secret).count(), 1);

    assert_eq!(engine::inspect_keys(b"not a key", now()), Err(EngineError::Malformed));
    assert_eq!(engine::inspect_keys(b"", now()), Err(EngineError::Malformed));
}

/// Armor headers may carry Latin-1 (old GnuPG `Comment:` lines).
#[test]
fn latin1_armor_header_is_accepted() {
    let alice = generate("Alice <alice@example.org>", None);
    let text = public_armor(&alice);
    let split = text.iter().position(|b| *b == b'\n').unwrap() + 1;
    let mut latin1 = text[..split].to_vec();
    latin1.extend_from_slice(b"Comment: caf\xe9\n");
    latin1.extend_from_slice(&text[split..]);
    assert_eq!(engine::inspect_keys(&latin1, now()).unwrap().len(), 1);
}

#[test]
fn import_keeps_only_what_was_checked_and_never_secret_material() {
    let alice = generate("Alice <alice@example.org>", None);
    let imported = engine::import_public(&secret_armor(&alice), now()).unwrap();
    assert_eq!(imported.keys.len(), 1);
    let text = String::from_utf8(imported.armored.to_vec()).unwrap();
    assert!(text.contains("PUBLIC KEY BLOCK"));
    assert!(!text.contains("PRIVATE"), "secret material must not be stored as a certificate");

    let secret = engine::import_secret(&secret_armor(&alice), now()).unwrap();
    assert!(String::from_utf8(secret.armored.to_vec()).unwrap().contains("PRIVATE KEY BLOCK"));
    assert!(secret.keys[0].has_secret);
    assert_eq!(engine::import_secret(&public_armor(&alice), now()).map(|_| ()),
               Err(EngineError::NoSecretKey));
}

#[test]
fn a_broken_key_is_not_imported() {
    let alice = generate("Alice <alice@example.org>", None);
    let mut cert = alice.to_public_key();
    let sig = cert.details.users[0].signatures[0].clone();
    cert.details.users[0].id =
        pgp::packet::UserId::from_str(Default::default(), "Mallory <mallory@example.net>").unwrap();
    cert.details.users[0].signatures = vec![sig];
    let armored = armor_public(&cert);
    assert_eq!(engine::inspect_keys(&armored, now()).unwrap()[0].validity, Validity::Broken);
    assert_eq!(engine::import_public(&armored, now()).map(|_| ()), Err(EngineError::Malformed));
    let data = b"payload";
    let result = engine::verify_detached(data, &detached(&alice, "", data), &armored, now()).unwrap();
    assert_eq!(result, vec![SignatureResult::Bad]);
}

/// A third-party certification on a user ID (common in GnuPG exports) must
/// not make a valid key look broken.
#[test]
fn third_party_certifications_do_not_break_a_key() {
    let alice = generate("Alice <alice@example.org>", None);
    let bob = generate("Bob <bob@example.net>", None);
    let mut cert = alice.to_public_key();
    let certified = cert.details.users[0]
        .id
        .sign_third_party(thread_rng(), &bob.primary_key, &Password::empty(), &cert.primary_key,
                          SignatureType::CertGeneric)
        .unwrap();
    cert.details.users[0].signatures.extend(certified.signatures);
    assert!(cert.verify_bindings().is_err(), "rPGP alone would call this key broken");

    let data = b"payload";
    let result = engine::verify_detached(data, &detached(&alice, "", data), &armor_public(&cert), now()).unwrap();
    assert!(good_signer(&result), "{result:?}");
}

#[test]
fn revoked_user_ids_are_left_out() {
    let alice = make(Spec { more_uids: &["Old <old@example.org>"], ..Default::default() });
    let mut cert = alice.to_public_key();
    let index = cert.details.users.iter().position(|u| u.id.as_str() == Some("Old <old@example.org>")).unwrap();
    let mut config = SignatureConfig::from_key(thread_rng(), &alice.primary_key,
                                               SignatureType::CertRevocation).unwrap();
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(alice.primary_key.fingerprint())).unwrap(),
    ];
    let revocation = config
        .sign_certification(&alice.primary_key, &cert.primary_key, &Password::empty(), Tag::UserId,
                            &cert.details.users[index].id)
        .unwrap();
    cert.details.users[index].signatures.push(revocation);
    let keys = engine::inspect_keys(&armor_public(&cert), now()).unwrap();
    assert_eq!(keys[0].user_ids, vec!["Alice <alice@example.org>".to_owned()]);
    assert_eq!(keys[0].validity, Validity::Valid, "a revoked user ID is not a revoked key");
}

/// A key revocation counts even with no issuer subpacket (the issuer is not
/// authenticated, so it is not used to pick which revocations to check).
#[test]
fn a_revoked_key_signs_nothing_valid() {
    let alice = generate("Alice <alice@example.org>", None);
    let mut cert = alice.to_public_key();
    let mut config = SignatureConfig::from_key(thread_rng(), &alice.primary_key,
                                               SignatureType::KeyRevocation).unwrap();
    config.hashed_subpackets =
        vec![Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap()];
    config.unhashed_subpackets = vec![];
    let revocation = config.sign_key(&alice.primary_key, &Password::empty(), &cert.primary_key).unwrap();
    cert.details.revocation_signatures.push(revocation);
    let armored = armor_public(&cert);
    assert_eq!(engine::inspect_keys(&armored, now()).unwrap()[0].validity, Validity::Revoked);
    let data = b"payload";
    let result = engine::verify_detached(data, &detached(&alice, "", data), &armored, now()).unwrap();
    assert!(key_not_valid(&result), "{result:?}");
}

/// Expiry comes from the newest self-signature of each bound user ID.
#[test]
fn an_expired_key_signs_nothing_valid() {
    let alice = generate("Alice <alice@example.org>", None);
    let mut cert = alice.to_public_key();
    let original = cert.details.users[0].signatures[0].config().unwrap().clone();
    let binding = retimed(&original, ts(1), vec![SubpacketData::KeyExpirationTime(days(1))])
        .sign_certification(&alice.primary_key, &cert.primary_key, &Password::empty(), Tag::UserId,
                            &cert.details.users[0].id)
        .unwrap();
    cert.details.users[0].signatures.push(binding);
    let armored = armor_public(&cert);
    let data = b"payload";
    let sig = detached(&alice, "", data);
    assert!(good_signer(&engine::verify_detached(data, &sig, &armored, now()).unwrap()));
    assert_eq!(engine::inspect_keys(&armored, later(2)).unwrap()[0].validity, Validity::Expired);
    assert!(key_not_valid(&engine::verify_detached(data, &sig, &armored, later(2)).unwrap()));
}

// MARK: - Signatures

#[test]
fn detached_good_bad_and_unknown() {
    let alice = generate("Alice <alice@example.org>", None);
    let data = b"Content-Type: text/plain\r\n\r\nHello\r\n";
    let sig = detached(&alice, "", data);
    let certs = public_armor(&alice);

    let good = engine::verify_detached(data, &sig, &certs, now()).unwrap();
    assert!(matches!(&good[..], [SignatureResult::Good { signer }]
        if signer.user_ids == ["Alice <alice@example.org>"]));

    let bad = engine::verify_detached(b"Content-Type: text/plain\r\n\r\nHellO\r\n", &sig, &certs, now()).unwrap();
    assert_eq!(bad, vec![SignatureResult::Bad]);

    let other = public_armor(&generate("Mallory <mallory@example.net>", None));
    let unknown = engine::verify_detached(data, &sig, &other, now()).unwrap();
    assert!(matches!(&unknown[..], [SignatureResult::UnknownKey { key_id }] if !key_id.is_empty()));

    let none = engine::verify_detached(data, &sig, b"", now()).unwrap();
    assert!(matches!(&none[..], [SignatureResult::UnknownKey { .. }]));
}

/// A text-mode signature hashes the text with CRLF line endings.
#[test]
fn text_signature_over_canonical_text() {
    let alice = generate("Alice <alice@example.org>", None);
    let sig = DetachedSignature::sign_text_data(thread_rng(), &alice.primary_key, &Password::empty(),
                                                HashAlgorithm::Sha256, &b"line one\nline two\n"[..])
        .unwrap()
        .to_armored_bytes(ArmorOptions::default())
        .unwrap();
    let result = engine::verify_detached(b"line one\r\nline two\r\n", &sig, &public_armor(&alice), now()).unwrap();
    assert!(good_signer(&result), "{result:?}");
}

/// SHA-1 data signatures read as unsupported, not good. rPGP itself refuses
/// SHA-1 with EdDSA and ECDSA, so the case to cover is RSA.
#[test]
fn weak_hashes_are_unsupported() {
    let dave = make(Spec { uid: "Dave <dave@example.net>", primary: KeyType::Rsa(2048),
                           encryption: KeyType::Rsa(2048), ..Default::default() });
    let data = b"payload";
    let certs = public_armor(&dave);
    let sha1 = detached_with(&dave, "", data, HashAlgorithm::Sha1);
    assert_eq!(engine::verify_detached(data, &sha1, &certs, now()).unwrap(),
               vec![SignatureResult::Unsupported]);
    let sha256 = detached_with(&dave, "", data, HashAlgorithm::Sha256);
    assert!(good_signer(&engine::verify_detached(data, &sha256, &certs, now()).unwrap()));
}

#[test]
fn signature_times_are_checked() {
    let alice = generate("Alice <alice@example.org>", None);
    let certs = public_armor(&alice);
    let data = b"payload";
    let base = DetachedSignature::sign_binary_data(thread_rng(), &alice.primary_key, &Password::empty(),
                                                   HashAlgorithm::Sha256, &data[..]).unwrap();
    let config = base.signature.config().unwrap().clone();
    let sign = |config: SignatureConfig| armor_sig(config.sign(&alice.primary_key, &Password::empty(), &data[..]).unwrap());

    let future = sign(retimed(&config, ts(86_400), vec![]));
    assert_eq!(engine::verify_detached(data, &future, &certs, now()).unwrap(), vec![SignatureResult::Bad]);

    let within_skew = sign(retimed(&config, ts(60), vec![]));
    assert!(good_signer(&engine::verify_detached(data, &within_skew, &certs, now()).unwrap()));

    let before_key = sign(retimed(&config, ts(-10 * 86_400), vec![]));
    assert_eq!(engine::verify_detached(data, &before_key, &certs, now()).unwrap(), vec![SignatureResult::Bad]);

    let expiring = sign(retimed(&config, ts(0), vec![SubpacketData::SignatureExpirationTime(days(1))]));
    assert!(good_signer(&engine::verify_detached(data, &expiring, &certs, now()).unwrap()));
    assert!(key_not_valid(&engine::verify_detached(data, &expiring, &certs, later(2)).unwrap()));
}

#[test]
fn the_primary_key_signs_data_only_with_the_sign_flag() {
    let alice = make(Spec { primary_signs: false, signing_subkey: true, ..Default::default() });
    let data = b"payload";
    let result = engine::verify_detached(data, &detached(&alice, "", data), &public_armor(&alice), now()).unwrap();
    assert!(key_not_valid(&result), "{result:?}");
}

fn subkey_sig(key: &SignedSecretKey, data: &[u8]) -> Vec<u8> {
    DetachedSignature::sign_binary_data(thread_rng(), &key.secret_subkeys[1].key, &Password::empty(),
                                        HashAlgorithm::Sha256, data)
        .unwrap()
        .to_armored_bytes(ArmorOptions::default())
        .unwrap()
}

#[test]
fn signing_subkey_good_revoked_and_expired() {
    let alice = make(Spec { signing_subkey: true, ..Default::default() });
    let data = b"payload";
    let sig = subkey_sig(&alice, data);
    assert!(good_signer(&engine::verify_detached(data, &sig, &public_armor(&alice), now()).unwrap()));

    // Revoked subkey: key_not_valid, not unknown_key.
    let mut revoked = alice.to_public_key();
    let mut config = SignatureConfig::from_key(thread_rng(), &alice.primary_key,
                                               SignatureType::SubkeyRevocation).unwrap();
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(alice.primary_key.fingerprint())).unwrap(),
    ];
    let revocation = config
        .sign_subkey_binding(&alice.primary_key, &revoked.primary_key, &Password::empty(),
                             &revoked.public_subkeys[1].key)
        .unwrap();
    revoked.public_subkeys[1].signatures.push(revocation);
    let result = engine::verify_detached(data, &sig, &armor_public(&revoked), now()).unwrap();
    assert!(key_not_valid(&result), "{result:?}");

    // Expired subkey: a newer binding with an expiry.
    let mut expiring = alice.to_public_key();
    let original = expiring.public_subkeys[1].signatures[0].config().unwrap().clone();
    let binding = retimed(&original, ts(1), vec![SubpacketData::KeyExpirationTime(days(1))])
        .sign_subkey_binding(&alice.primary_key, &expiring.primary_key, &Password::empty(),
                             &expiring.public_subkeys[1].key)
        .unwrap();
    expiring.public_subkeys[1].signatures.push(binding);
    let armored = armor_public(&expiring);
    assert!(good_signer(&engine::verify_detached(data, &sig, &armored, now()).unwrap()));
    assert!(key_not_valid(&engine::verify_detached(data, &sig, &armored, later(2)).unwrap()));
}

#[test]
fn signature_count_is_capped_and_duplicates_removed() {
    let alice = generate("Alice <alice@example.org>", None);
    let certs = public_armor(&alice);
    let data = b"payload";
    let one = detached(&alice, "", data);
    let twice = [one.clone(), one.clone()].concat();
    assert_eq!(engine::verify_detached(data, &twice, &certs, now()).unwrap().len(), 1);

    let many: Vec<u8> = (0..17u8).flat_map(|i| detached(&alice, "", &[i])).collect();
    assert_eq!(engine::verify_detached(data, &many, &certs, now()), Err(EngineError::Malformed));
}

#[test]
fn malformed_inputs_are_errors_not_panics() {
    let alice = generate("Alice <alice@example.org>", None);
    let certs = public_armor(&alice);
    for garbage in [&b""[..], b"-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n",
                    b"\x89\x01\x02", b"plain text"] {
        assert_eq!(engine::verify_detached(b"data", garbage, &certs, now()), Err(EngineError::Malformed));
        assert!(engine::decrypt(garbage, &secret_armor(&alice), b"", b"", now()).is_err());
        assert!(engine::verify_cleartext(garbage, &certs, now()).is_err());
    }
    assert_eq!(engine::verify_detached(b"data", &detached(&alice, "", b"data"), b"junk", now()),
               Err(EngineError::Malformed));
    let huge = vec![b'a'; engine::MAX_INPUT + 1];
    assert_eq!(engine::verify_detached(&huge, b"x", &certs, now()), Err(EngineError::TooLarge));
}

#[test]
fn cleartext_signed_text_is_what_was_signed() {
    let alice = generate("Alice <alice@example.org>", None);
    let msg = CleartextSignedMessage::sign(thread_rng(), "Hello\n- dashes\n", &alice.primary_key,
                                           &Password::empty())
        .unwrap()
        .to_armored_bytes(ArmorOptions::default())
        .unwrap();
    let result = engine::verify_cleartext(&msg, &public_armor(&alice), now()).unwrap();
    assert!(good_signer(&result.signatures));
    assert_eq!(String::from_utf8(result.signed_text).unwrap(), "Hello\r\n- dashes\r\n");
}

/// Ed448 and X448 rely on the unaudited cx448 crate: refused.
#[test]
fn ed448_and_x448_are_unsupported() {
    let carol = make(Spec { uid: "Carol <carol@example.net>", primary: KeyType::Ed448,
                            encryption: KeyType::X448, hash: HashAlgorithm::Sha512,
                            ..Default::default() });
    let armored = public_armor(&carol);
    assert_eq!(engine::inspect_keys(&armored, now()).unwrap()[0].validity, Validity::Unsupported);
    assert_eq!(engine::import_public(&armored, now()).map(|_| ()), Err(EngineError::Malformed));
    assert_eq!(engine::import_secret(&secret_armor(&carol), now()).map(|_| ()), Err(EngineError::NoSecretKey));
    let data = b"payload";
    let result = engine::verify_detached(data, &detached_with(&carol, "", data, HashAlgorithm::Sha512),
                                         &armored, now()).unwrap();
    assert_eq!(result, vec![SignatureResult::Unsupported]);
    let msg = encrypt(&carol, None, true, b"secret");
    assert_eq!(engine::decrypt(&msg, &secret_armor(&carol), b"", b"", now()).map(|_| ()),
               Err(EngineError::Unsupported));
}

// MARK: - Decryption

fn encrypt(to: &SignedSecretKey, signer: Option<&SignedSecretKey>, v2: bool, plaintext: &[u8]) -> Vec<u8> {
    encrypt_with(to, signer, v2, plaintext, None, true)
}

fn encrypt_with(to: &SignedSecretKey, signer: Option<&SignedSecretKey>, v2: bool, plaintext: &[u8],
                compression: Option<CompressionAlgorithm>, armored: bool) -> Vec<u8> {
    let mut rng = thread_rng();
    let public = to.to_public_key();
    let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec());
    if let Some(c) = compression {
        builder.compression(c);
    }
    macro_rules! finish {
        ($b:expr) => {{
            let mut b = $b;
            b.encrypt_to_key(&mut rng, &public.public_subkeys[0]).unwrap();
            if let Some(s) = signer {
                b.sign(&s.primary_key, Password::empty(), HashAlgorithm::Sha256);
            }
            if armored {
                b.to_armored_string(&mut rng, ArmorOptions::default()).unwrap().into_bytes()
            } else {
                b.to_vec(&mut rng).unwrap()
            }
        }};
    }
    if v2 {
        finish!(builder.seipd_v2(&mut rng, SymmetricKeyAlgorithm::AES256,
                                 pgp::crypto::aead::AeadAlgorithm::Ocb,
                                 pgp::crypto::aead::ChunkSize::default()))
    } else {
        finish!(builder.seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256))
    }
}

#[test]
fn decrypt_round_trips_with_integrity_and_inner_signature() {
    let alice = generate("Alice <alice@example.org>", None);
    let bob = generate("Bob <bob@example.net>", None);
    for v2 in [false, true] {
        let msg = encrypt(&bob, Some(&alice), v2, b"secret text");
        let out = engine::decrypt(&msg, &secret_armor(&bob), b"", &public_armor(&alice), now()).unwrap();
        assert_eq!(out.plaintext.as_slice(), b"secret text");
        assert!(out.integrity_protected);
        assert!(matches!(&out.signatures[..], [SignatureResult::Good { signer }]
            if signer.user_ids == ["Alice <alice@example.org>"]), "v2={v2}: {:?}", out.signatures);

        let out = engine::decrypt(&msg, &secret_armor(&bob), b"", b"", now()).unwrap();
        assert!(matches!(&out.signatures[..], [SignatureResult::UnknownKey { .. }]));
    }
}

/// Compressed and signed-then-compressed content comes back as the
/// original text, not as compressed bytes.
#[test]
fn compressed_content_is_decompressed() {
    let alice = generate("Alice <alice@example.org>", None);
    let bob = generate("Bob <bob@example.net>", None);
    let text = b"compress me ".repeat(100);
    for signer in [None, Some(&alice)] {
        let msg = encrypt_with(&bob, signer, true, &text, Some(CompressionAlgorithm::ZLIB), true);
        let out = engine::decrypt(&msg, &secret_armor(&bob), b"", &public_armor(&alice), now()).unwrap();
        assert_eq!(out.plaintext.as_slice(), &text[..], "signed: {}", signer.is_some());
    }
}

#[test]
fn a_compression_bomb_stops_at_the_limit() {
    let bob = generate("Bob <bob@example.net>", None);
    let zeros = vec![0u8; engine::MAX_PLAINTEXT as usize + 1024];
    let msg = encrypt_with(&bob, None, true, &zeros, Some(CompressionAlgorithm::ZLIB), false);
    assert!(msg.len() < 1024 * 1024, "the ciphertext is small: {}", msg.len());
    assert_eq!(engine::decrypt(&msg, &secret_armor(&bob), b"", b"", now()).map(|_| ()),
               Err(EngineError::TooLarge));
}

#[test]
fn decrypt_errors() {
    let bob = generate("Bob <bob@example.net>", None);
    let eve = generate("Eve <eve@example.net>", None);
    let msg = encrypt(&bob, None, true, b"secret");
    assert_eq!(engine::decrypt(&msg, &secret_armor(&eve), b"", b"", now()).map(|_| ()),
               Err(EngineError::NoSecretKey));
    assert_eq!(engine::decrypt(&msg, &public_armor(&bob), b"", b"", now()).map(|_| ()),
               Err(EngineError::NoSecretKey), "a public key cannot decrypt");

    let locked = generate("Carol <carol@example.net>", Some("correct horse"));
    let msg = encrypt(&locked, None, true, b"secret");
    for pw in [&b"wrong"[..], b""] {
        assert_eq!(engine::decrypt(&msg, &secret_armor(&locked), pw, b"", now()).map(|_| ()),
                   Err(EngineError::PassphraseRequired));
    }
    let right = engine::decrypt(&msg, &secret_armor(&locked), b"correct horse", b"", now()).unwrap();
    assert_eq!(right.plaintext.as_slice(), b"secret");
}

/// A modified MDC (SEIPD v1) or AEAD tag (v2): an integrity failure, no plaintext.
#[test]
fn tampered_ciphertext_is_an_integrity_failure() {
    let bob = generate("Bob <bob@example.net>", None);
    for v2 in [false, true] {
        let mut binary = encrypt_with(&bob, None, v2, &[b'x'; 4096], None, false);
        let at = binary.len() - 10;
        binary[at] ^= 0x01;
        let out = engine::decrypt(&binary, &secret_armor(&bob), b"", b"", now());
        assert_eq!(out.map(|_| ()), Err(EngineError::NotIntegrityProtected), "v2={v2}");
    }
}

/// Packets of a binary message: (tag, body), new or old format headers.
fn packets(mut data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while let Some((&first, rest)) = data.split_first() {
        data = rest;
        let (tag, mut body) = if first & 0x40 != 0 {
            let tag = first & 0x3f;
            let mut body = Vec::new();
            loop {
                let (len, partial, used) = match data[0] {
                    l @ 0..=191 => (l as usize, false, 1),
                    l @ 192..=223 => ((((l as usize) - 192) << 8) + data[1] as usize + 192, false, 2),
                    255 => (u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize, false, 5),
                    l => (1usize << (l & 0x1f), true, 1),
                };
                body.extend_from_slice(&data[used..used + len]);
                data = &data[used + len..];
                if !partial {
                    break;
                }
            }
            (tag, body)
        } else {
            let tag = (first >> 2) & 0x0f;
            let (len, used) = match first & 3 {
                0 => (data[0] as usize, 1),
                1 => (u16::from_be_bytes([data[0], data[1]]) as usize, 2),
                2 => (u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize, 4),
                _ => (data.len(), 0),
            };
            let body = data[used..used + len].to_vec();
            data = &data[used + len..];
            (tag, body)
        };
        out.push((tag, std::mem::take(&mut body)));
    }
    out
}

fn packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0xC0 | tag, 255];
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Legacy SED (no integrity protection): refused before decryption.
#[test]
fn a_message_without_integrity_protection_is_refused() {
    let bob = generate("Bob <bob@example.net>", None);
    let seipd = encrypt_with(&bob, None, false, b"secret", None, false);
    let sed: Vec<u8> = packets(&seipd)
        .into_iter()
        .flat_map(|(tag, body)| if tag == 18 { packet(9, &body[1..]) } else { packet(tag, &body) })
        .collect();
    assert_eq!(engine::decrypt(&sed, &secret_armor(&bob), b"", b"", now()).map(|_| ()),
               Err(EngineError::NotIntegrityProtected));
}

// MARK: - FFI

#[test]
fn ffi_round_trip_clock_and_garbage() {
    use mishmail_rpgp::{mm_pgp_free, mm_pgp_import_public, mm_pgp_inspect_keys, mm_pgp_verify_detached};
    let alice = generate("Alice <alice@example.org>", None);
    let certs = public_armor(&alice);
    let data = b"payload";
    let sig = detached(&alice, "", data);
    let unix = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;
    let json = |r: &mishmail_rpgp::MMResult| unsafe {
        std::str::from_utf8(std::slice::from_raw_parts(r.json.ptr, r.json.len)).unwrap().to_owned()
    };
    unsafe {
        let r = mm_pgp_verify_detached(data.as_ptr(), data.len(), sig.as_ptr(), sig.len(),
                                       certs.as_ptr(), certs.len(), unix);
        assert!(json(&r).contains("\"ok\":true") && json(&r).contains("\"status\":\"good\""), "{}", json(&r));
        assert!(r.data.ptr.is_null());
        mm_pgp_free(r);

        // No clock: refused, not read as 1970 (which would hide every expiry).
        for bad in [0, -1] {
            let r = mm_pgp_verify_detached(data.as_ptr(), data.len(), sig.as_ptr(), sig.len(),
                                           certs.as_ptr(), certs.len(), bad);
            assert_eq!(json(&r), r#"{"error":"internal","ok":false}"#);
            mm_pgp_free(r);
        }

        let r = mm_pgp_inspect_keys(b"\xff\xfe".as_ptr(), 2, unix);
        assert_eq!(json(&r), r#"{"error":"malformed","ok":false}"#);
        mm_pgp_free(r);

        let secret = secret_armor(&alice);
        let r = mm_pgp_import_public(secret.as_ptr(), secret.len(), unix);
        assert!(json(&r).contains("\"validity\":\"valid\""), "{}", json(&r));
        let stored = std::slice::from_raw_parts(r.data.ptr, r.data.len);
        assert!(!String::from_utf8_lossy(stored).contains("PRIVATE"));
        mm_pgp_free(r);

        let r = mm_pgp_verify_detached(std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null(), 0, unix);
        mm_pgp_free(r);
    }
}
