// Link check for the built library (CI only): calls one function through
// the C interface and frees the result. It proves that Apple's linker
// accepts the static library and that a call crosses the boundary; the
// engine's behaviour is covered by the Rust tests.
#include <stdio.h>
#include <string.h>
#include "mishmail_rpgp.h"

int main(void) {
    const uint8_t empty[1] = {0};
    MMResult result = mm_pgp_inspect_keys(empty, 0, 1700000000);
    if (result.json.ptr == NULL || result.json.len == 0) {
        fprintf(stderr, "no JSON answer\n");
        return 1;
    }
    if (memchr(result.json.ptr, '{', result.json.len) == NULL) {
        fprintf(stderr, "answer is not JSON\n");
        return 1;
    }
    printf("%.*s\n", (int)result.json.len, (const char *)result.json.ptr);
    mm_pgp_free(result);
    return 0;
}
