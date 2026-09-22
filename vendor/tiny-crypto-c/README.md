# tiny-crypto-c EC source

This directory contains the EC-only source slice from
[`tiny-crypto-c` commit e5bf501735a36bcf9581754a3ef7717486dbc3da](https://github.com/mistial-dev/tiny-crypto-c/commit/e5bf501735a36bcf9581754a3ef7717486dbc3da).
The files are copied without local modifications. Their SPDX notices identify
GPL-2.0-or-later; the upstream license text is retained in `LICENSE`.
The Rust bridge uses AGPL-3.0-or-later. The GPLv3 option permitted by the C
files' "or later" notices can be combined with AGPLv3 under GPLv3 section 13,
as described by the [GNU license FAQ](https://www.gnu.org/licenses/gpl-faq.en.html#v2v3Compatibility)
and [GPLv3 text](https://www.gnu.org/licenses/gpl-3.0.html#section13). Each
source file retains its own license notice.

The board uses CC310 for P-256. This slice is intended only for curves or
operations CC310 does not provide. The Rust bridge compiles just `ec.c` and
`common.c` with explicit curve and zeroization options. It does not enable a
software retry after CC310 failure.

Update by selecting an upstream commit, copying these eight source and header
files, and running the EC known-answer, negative, sanitizer, and board-link
checks before changing this pin. The source is vendored so release builds do
not fetch code from the network.
