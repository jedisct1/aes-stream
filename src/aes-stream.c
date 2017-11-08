#include "aes-stream.h"

#if defined(__GNUC__) && !defined(__clang__)
# pragma GCC target("ssse3")
# pragma GCC target("aes")
#endif

#include <immintrin.h>
#include <stdint.h>
#include <stdlib.h>

#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])

#if defined(__IBMC__) || defined(__SUNPRO_C) || defined(__SUNPRO_CC)
# pragma pack(1)
#else
# pragma pack(push, 1)
#endif

typedef struct CRYPTO_ALIGN(16) _aes_stream_state {
    __m128i round_keys[AES_STREAM_ROUNDS + 1];
    __m128i counter;
} _aes_stream_state;

#if defined(__IBMC__) || defined(__SUNPRO_C) || defined(__SUNPRO_CC)
# pragma pack()
#else
# pragma pack(pop)
#endif

#define DRC(ROUND, RC)                                       \
    do {                                                     \
        s = _mm_aeskeygenassist_si128(t1, (RC));             \
        round_keys[ROUND] = t1;                              \
        t1 = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));       \
        t1 = _mm_xor_si128(t1, _mm_slli_si128(t1, 8));       \
        t1 = _mm_xor_si128(t1, _mm_shuffle_epi32(s, 0xff));  \
    } while (0)

#define DRC2(ROUND, RC)                                      \
    do {                                                     \
        s = _mm_aeskeygenassist_si128(t2, (RC));             \
        round_keys[ROUND] = t2;                              \
        t2 = _mm_xor_si128(t2, _mm_slli_si128(t1, 4));       \
        t2 = _mm_xor_si128(t2, _mm_slli_si128(t1, 8));       \
        t2 = _mm_xor_si128(t2, _mm_shuffle_epi32(s, 0xaa));  \
    } while (0)

#if AES_STREAM_ROUNDS == 10
static void
_aes_key_expand_128(__m128i round_keys[AES_STREAM_ROUNDS + 1], __m128i t1)
{
    __m128i s;

    DRC(0, 1); DRC(1, 2); DRC(2, 4); DRC(3, 8); DRC(4, 16);
    DRC(5, 32); DRC(6, 64); DRC(7, 128); DRC(8, 27); DRC(9, 54);
    round_keys[10] = t1;
}

#elif AES_STREAM_ROUNDS == 14

static void
_aes_key_expand_256(__m128i round_keys[AES_STREAM_ROUNDS + 1],
                    __m128i t1, __m128i t2)
{
    __m128i s;

    round_keys[0] = t1;
    DRC(1, 1); DRC2(2, 1); DRC(3, 2); DRC2(4, 2);
    DRC(5, 4); DRC2(6, 4); DRC(7, 8); DRC2(8, 8);
    DRC(9, 16); DRC2(10, 16); DRC(11, 32); DRC2(12, 32);
    DRC(13, 64);
    round_keys[14] = t1;
}
#endif

static void
_aes_stream(_aes_stream_state *_st, unsigned char *buf, size_t buf_len)
{
    CRYPTO_ALIGN(16) unsigned char t[16];
    const __m128i  one = _mm_set_epi64x(0, 1);
    const __m128i  two = _mm_set_epi64x(0, 2);
    __m128i       *round_keys = _st->round_keys;
    __m128i        c0, c1, c2, c3, c4, c5, c6, c7;
    __m128i        r0, r1, r2, r3, r4, r5, r6, r7;
    __m128i        s0, s1, s2, s3, s4, s5, s6, s7;
    size_t         i;
    size_t         remaining;

#if AES_STREAM_ROUNDS == 10
# define COMPUTE_AES_STREAM_ROUNDS(N)                                                  \
    do {                                                                               \
        r##N = _mm_aesenc_si128(   _mm_xor_si128(c##N, round_keys[0]), round_keys[1]); \
        r##N = _mm_aesenc_si128(_mm_aesenc_si128(r##N, round_keys[2]), round_keys[3]); \
        r##N = _mm_aesenc_si128(_mm_aesenc_si128(r##N, round_keys[4]), round_keys[5]); \
        s##N = r##N;                                                                   \
        r##N = _mm_aesenc_si128(_mm_aesenc_si128(r##N, round_keys[6]), round_keys[7]); \
        r##N = _mm_aesenc_si128(_mm_aesenc_si128(r##N, round_keys[8]), round_keys[9]); \
        r##N = _mm_xor_si128(s##N, _mm_aesenclast_si128(r##N, round_keys[10]));        \
    } while (0)

#elif AES_STREAM_ROUNDS == 14

# define COMPUTE_AES_STREAM_ROUNDS(N)                                                    \
    do {                                                                                 \
        r##N = _mm_aesenc_si128(   _mm_xor_si128(c##N, round_keys[ 0]), round_keys[ 1]); \
        r##N = _mm_aesenc_si128(_mm_aesenc_si128(r##N, round_keys[ 2]), round_keys[ 3]); \
        r##N = _mm_aesenc_si128(_mm_aesenc_si128(r##N, round_keys[ 4]), round_keys[ 5]); \
        r##N = _mm_aesenc_si128(_mm_aesenc_si128(r##N, round_keys[ 6]), round_keys[ 7]); \
        s##N = r##N;                                                                     \
        r##N = _mm_aesenc_si128(_mm_aesenc_si128(r##N, round_keys[ 8]), round_keys[ 9]); \
        r##N = _mm_aesenc_si128(_mm_aesenc_si128(r##N, round_keys[10]), round_keys[11]); \
        r##N = _mm_aesenc_si128(_mm_aesenc_si128(r##N, round_keys[12]), round_keys[13]); \
        r##N = _mm_xor_si128(s##N, _mm_aesenclast_si128(r##N, round_keys[14]));          \
    } while (0)
#endif

    c0 = _st->counter;
    remaining = buf_len;
    while (remaining > 128) {
        c1 = _mm_add_epi64(c0, one);
        c2 = _mm_add_epi64(c0, two);
        c3 = _mm_add_epi64(c2, one);
        c4 = _mm_add_epi64(c2, two);
        c5 = _mm_add_epi64(c4, one);
        c6 = _mm_add_epi64(c4, two);
        c7 = _mm_add_epi64(c6, one);
        COMPUTE_AES_STREAM_ROUNDS(0);
        COMPUTE_AES_STREAM_ROUNDS(1);
        COMPUTE_AES_STREAM_ROUNDS(2);
        COMPUTE_AES_STREAM_ROUNDS(3);
        COMPUTE_AES_STREAM_ROUNDS(4);
        COMPUTE_AES_STREAM_ROUNDS(5);
        COMPUTE_AES_STREAM_ROUNDS(6);
        COMPUTE_AES_STREAM_ROUNDS(7);
        c0 = _mm_add_epi64(c7, one);
        _mm_storeu_si128((__m128i *) (void *) (buf +   0), r0);
        _mm_storeu_si128((__m128i *) (void *) (buf +  16), r1);
        _mm_storeu_si128((__m128i *) (void *) (buf +  32), r2);
        _mm_storeu_si128((__m128i *) (void *) (buf +  48), r3);
        _mm_storeu_si128((__m128i *) (void *) (buf +  64), r4);
        _mm_storeu_si128((__m128i *) (void *) (buf +  80), r5);
        _mm_storeu_si128((__m128i *) (void *) (buf +  96), r6);
        _mm_storeu_si128((__m128i *) (void *) (buf + 112), r7);
        buf += 128;
        remaining -= 128;
    }
    while (remaining > 32) {
        c1 = _mm_add_epi64(c0, one);
        COMPUTE_AES_STREAM_ROUNDS(0);
        COMPUTE_AES_STREAM_ROUNDS(1);
        c0 = _mm_add_epi64(c1, one);
        _mm_storeu_si128((__m128i *) (void *) (buf +  0), r0);
        _mm_storeu_si128((__m128i *) (void *) (buf + 16), r1);
        buf += 32;
        remaining -= 32;
    }
    while (remaining > 16) {
        COMPUTE_AES_STREAM_ROUNDS(0);
        c0 = _mm_add_epi64(c0, one);
        _mm_storeu_si128((__m128i *) (void *) buf, r0);
        buf += 16;
        remaining -= 16;
    }
    if (remaining > (size_t) 0U) {
        COMPUTE_AES_STREAM_ROUNDS(0);
        c0 = _mm_add_epi64(c0, one);
        _mm_store_si128((__m128i *) (void *) t, r0);
        for (i = 0; i < remaining; i++) {
            buf[i] = t[i];
        }
    }
    _st->counter = c0;

    c0 = _mm_xor_si128(c0, _mm_set_epi64x(1ULL << 63, 0));

#if AES_STREAM_ROUNDS == 10
    COMPUTE_AES_STREAM_ROUNDS(0);
    _aes_key_expand_128(round_keys, r0);

#elif AES_STREAM_ROUNDS == 14

    c1 = _mm_add_epi64(c0, one);
    COMPUTE_AES_STREAM_ROUNDS(0);
    COMPUTE_AES_STREAM_ROUNDS(1);
    _aes_key_expand_256(round_keys, r0, r1);
#endif
}

void
aes_stream_init(aes_stream_state *st,
                const unsigned char seed[AES_STREAM_SEEDBYTES])
{
    _aes_stream_state *_st = (_aes_stream_state *) (void *) st;

    COMPILER_ASSERT(sizeof *st >= sizeof *_st);

#if AES_STREAM_ROUNDS == 10
    _aes_key_expand_128(_st->round_keys,
                        _mm_loadu_si128((const __m128i *) (const void *) seed));
    _st->counter = _mm_loadu_si128((const __m128i *) (const void *) (seed + 16));

#elif AES_STREAM_ROUNDS == 14

    _aes_key_expand_256(_st->round_keys,
                        _mm_loadu_si128((const __m128i *) (const void *) seed),
                        _mm_loadu_si128((const __m128i *) (const void *) (seed + 16)));
    _st->counter = _mm_setzero_si128();
#endif
}

void
aes_stream(aes_stream_state *st, unsigned char *buf, size_t buf_len)
{
    _aes_stream((_aes_stream_state *) (void *) st, buf, buf_len);
}
