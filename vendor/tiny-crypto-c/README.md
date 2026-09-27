# tiny-crypto-c source

This directory contains the EC source slice from
[`tiny-crypto-c` commit c485a1e3fb6c8f632f3523ce314e49c3312e3c0c](https://github.com/mistial-dev/tiny-crypto-c/commit/c485a1e3fb6c8f632f3523ce314e49c3312e3c0c).
`sha512.c` and `tiny_crypto/hash.h` come from
[`b376ce0251d73b32c444c76749ba30fcc3834c46`](https://github.com/mistial-dev/tiny-crypto-c/commit/b376ce0251d73b32c444c76749ba30fcc3834c46).
`des.c`, `tiny_crypto/des.h`, and the DES ISO 9797 selection in
`tiny_crypto/config.h` come from
[`003caed622580829c7e36b583bbe4084663b2ed5`](https://github.com/mistial-dev/tiny-crypto-c/commit/003caed622580829c7e36b583bbe4084663b2ed5).
The ISO 9797 addition is proposed upstream in
[`tiny-crypto-c` PR 2](https://github.com/mistial-dev/tiny-crypto-c/pull/2).
The sources are copied without local modifications. Their SPDX notices identify
GPL-2.0-or-later; the upstream license text is retained in `LICENSE`.
The Rust bridge uses AGPL-3.0-or-later. The GPLv3 option permitted by the C
files' "or later" notices can be combined with AGPLv3 under GPLv3 section 13,
as described by the [GNU license FAQ](https://www.gnu.org/licenses/gpl-faq.en.html#v2v3Compatibility)
and [GPLv3 text](https://www.gnu.org/licenses/gpl-3.0.html#section13). Each
source file retains its own license notice.

The board uses CC310 for P-256. This slice is intended only for curves or
operations CC310 does not provide. The Rust bridge compiles `ec.c`, `sha512.c`,
and `common.c` with explicit curve, digest, and zeroization options. The optional
`des-legacy` crate feature additionally compiles `des.c` for ECB, CBC, and ISO
9797-1 algorithm 1 and 3 MACs. The crate feature defaults off; the standard
JCVM board build selects it, while the compact build omits it. Java Card
padding and factory selection remain outside the C library. It does not enable
a software retry after CC310 failure.

Update by selecting an upstream commit, copying the used sources and headers,
and running the EC and digest known-answer, negative, sanitizer, and board-link
checks before changing this pin. The source is vendored so release builds do
not fetch code from the network.
