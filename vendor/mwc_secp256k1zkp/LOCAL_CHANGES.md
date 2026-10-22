# Pinned secp256k1 backend experiment

Source: https://github.com/mwcproject/rust-secp256k1-zkp
Tag: 0.8.0; revision: ddb7ae905c34c12df11087bc602727969c2e3838.
Staged using `cargo vendor`; upstream Rust and C cryptographic implementations
and licenses are unchanged. Cargo normalized the manifest during vendoring.
The workspace uses a path patch, not Cargo directory-source replacement.
The generated `.cargo-checksum.json` was removed because local metadata is
modified; it must not be presented as a pristine directory-source checksum.
Upstream implementation files can be compared with the pinned git revision.

Local changes: `build.rs` chooses the existing 5x52 field / 4x64 scalar backend
with unsigned __int128 on Apple aarch64 only; other targets retain upstream
10x26 / 8x32. `MWC_SECP_BACKEND=32` forces the original implementation for A/B
tests; `64` is rejected on other targets. Selection is printed in Cargo logs.
No architecture-specific CPU instruction flags or fast-math are enabled.
`examples/backend-check.rs` and its manifest entry add a deterministic fixture
and commitment parsing, Bulletproof verification, and ECDSA verification bench.
The local Cargo.lock pins test dependencies, including upstream locked versions.

Tests must run for both backends, with release optimization. Compare the complete
`fixture` output byte-for-byte. The fixture additionally rejects an incorrect
commitment and a corrupted proof. Full upstream Rust tests cover more invalid
keys/signatures/proofs. C tests must use upstream Makefile's `SECP256K1_BUILD`
define plus `VERIFY`; omitting the former incorrectly enables compiler nonnull
assumptions in a harness that deliberately tests null arguments.

Primitive and verification speedups on an arm64 Mac are not an iPhone blocks/sec
measurement. Keep device validation and sustained sync measurements separate.

## Local validation, 2026-09-11

Both backends: optimized Rust suite 64 passed, 1 ignored (upstream benchmark);
upstream C tests with all production-enabled modules, VERIFY and O3, count 8,
seed 0123456789abcdef0123456789abcdef: no problems found and identical final
random run c64f691ca8a5251927739f5e4e39fc0f. Initial direct C harness invocations
without SECP256K1_BUILD failed; using the upstream-required flag resolved this
for both backends, without changing tests or cryptographic implementation.

Sequential optimized A/B then B/A on the local Apple arm64 Mac:

| Operation | Original 32-bit microseconds | 64-bit microseconds |
| --- | ---: | ---: |
| Commitment parse/validation | 13.47–14.16 | 8.23–8.85 |
| Single Bulletproof verification | 1340.7–1345.0 | 849.0–852.5 |
| ECDSA verification | 37.80–39.22 | 20.41–20.50 |

All four deterministic fixture lines were byte-identical. These are short
microbenchmarks, not statistical confidence intervals or sustained thermal tests.
Run `bash scripts/test-secp-backends.sh` from the outer repository to repeat;
its temporary output is retained, not deleted. Cargo lockfiles preserve the
existing dependency versions; no crypto version upgrade is included.
