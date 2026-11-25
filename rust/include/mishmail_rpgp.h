// C interface of the dreamail-openpgp library (MishMail's OpenPGP engine
// over rPGP). Hand-written to match src/lib.rs; the build script checks that
// the exported symbols match the functions declared here.
//
// Every call is synchronous and may take time (key parsing, decryption):
// call it off the main thread. `now_unix` is the caller's clock in seconds;
// zero or negative is refused. Every result must be freed exactly once with
// mm_pgp_free, which zeroes both buffers first.
#ifndef MISHMAIL_RPGP_H
#define MISHMAIL_RPGP_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *ptr;  // NULL when len is 0; owned by the library
    size_t len;
} MMBuffer;

typedef struct {
    MMBuffer json;  // UTF-8 {"ok":true,...} or {"ok":false,"error":"..."}
    MMBuffer data;  // plaintext, signed text or re-serialized keys; empty otherwise
} MMResult;

MMResult mm_pgp_verify_detached(const uint8_t *data, size_t data_len,
                                const uint8_t *signature, size_t signature_len,
                                const uint8_t *certs, size_t certs_len,
                                int64_t now_unix);
MMResult mm_pgp_verify_cleartext(const uint8_t *message, size_t message_len,
                                 const uint8_t *certs, size_t certs_len,
                                 int64_t now_unix);
MMResult mm_pgp_decrypt(const uint8_t *message, size_t message_len,
                        const uint8_t *secret_keys, size_t secret_keys_len,
                        const uint8_t *passphrase, size_t passphrase_len,
                        const uint8_t *certs, size_t certs_len,
                        int64_t now_unix);
// What the keys are, with their validity; `data` is empty.
MMResult mm_pgp_inspect_keys(const uint8_t *data, size_t data_len, int64_t now_unix);
// Public keys that may be stored (not broken, supported algorithm),
// re-serialized in `data`; never secret material.
MMResult mm_pgp_import_public(const uint8_t *data, size_t data_len, int64_t now_unix);
// Valid secret keys, re-serialized in `data` under their own passphrase.
MMResult mm_pgp_import_secret(const uint8_t *data, size_t data_len, int64_t now_unix);
void mm_pgp_free(MMResult result);

#endif
