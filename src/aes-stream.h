#ifndef aes_stream_H
#define aes_stream_H

#include <stdlib.h>

#ifndef CRYPTO_ALIGN
# if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#  define CRYPTO_ALIGN(x) __declspec(align(x))
# else
#  define CRYPTO_ALIGN(x) __attribute__((aligned(x)))
# endif
#endif

typedef struct CRYPTO_ALIGN(16) aes_stream_state {
    unsigned char opaque[11 * 16 + 16];
} aes_stream_state;

#define AES_STREAM_KEYBYTES 16

void aes_stream_init(aes_stream_state *st,
                     const unsigned char key[AES_STREAM_KEYBYTES]);

void aes_stream(unsigned char *buf, size_t buf_len, aes_stream_state *st);

#endif
