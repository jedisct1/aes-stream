AES-STREAM
==========

A simple, but fast AES-PRF-based random number generator.

Fast, designed to fill large buffers with random data.
Does fast key erasure.

Requires a modern Intel or AMD CPU with AES-NI support.

API
===

Pretty straightforward:

```c
#include "aes-stream.h"

#define AES_STREAM_SEEDBYTES 32

void aes_stream_init(aes_stream_state *st, const unsigned char seed[AES_STREAM_SEEDBYTES]);

void aes_stream(aes_stream_state *st, unsigned char *buf, size_t buf_len);
```

Call `aes_stream_init()` with a seed, then `aes_stream()` to fill
`buf` with `buf_len` random bytes.

`aes_stream()` can be called indefinitely without having to reseed the
generator.

Compilation
===========

Do not forget to tell your compiler to enable support for AES opcodes
with the `-maes` flag.

Recommended: `-Ofast -maes -march=native`

Clang 5 appears to produce faster code than gcc 7.

Key erasure is performed after every call to `stream()`. If you are
dealing with many short keys, implement a pool on top of this.

References
==========

* [Optimal PRFs from blockcipher designs](https://eprint.iacr.org/2017/812.pdf)
(Bart Mennink and Samuel Neves)
* [Fast-key-erasure random-number generators](https://blog.cr.yp.to/20170723-random.html)
(Daniel J. Bernstein)
