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

#define AES_STREAM_KEYBYTES 16

void aes_stream_init(aes_stream_state *st, const unsigned char key[AES_STREAM_KEYBYTES]);

void aes_stream(unsigned char *buf, size_t buf_len, aes_stream_state *st);
```

Call `aes_stream_init()` with a seed, then `aes_stream()` to fill
`buf` with `buf_len` random bytes.

`aes_stream()` can be called indefinitely without having to reseed the
generator.

Compilation
===========

Do not forget to tell your compiler to enable support for AES opcodes
with the `-maes` flag.

Recommended: `-O3 -maes -march=native`

By default, key erasure is performed after every call to `stream()`.

If you are producing a lot of short keys, this can be disabled by
declaring a `FAST_KEY_ERASURE` macro with a value of `0`.

References
==========

* [Optimal PRFs from blockcipher designs](https://eprint.iacr.org/2017/812.pdf)
(Bart Mennink and Samuel Neves)
* [Fast-key-erasure random-number generators](https://blog.cr.yp.to/20170723-random.html)
(Daniel J. Bernstein)
