# Verified Rust Implementations of FIPS 140-3 Algorithms

This repository builds towards verified Rust implementations of FIPS 140-3 algorithms. Proofs are built by converting Rust code to equivalent Lean code using Aeneas, then proving these conversions against Lean specifications. At this time, no algorithms have been verified.

Currently, this repository contains the following pieces:

[Rust reference implementations](./rust/src/algorithms) (and their [conversions to Lean](./lean/VerifiedFipsCryptography/RustTranslations/FipsImplementations.lean)):
- SHA-1
- AES

[Lean specifications](./lean/VerifiedFipsCryptography/Specs):
- SHA-1
- AES

[Verified implementations](./lean/VerifiedFipsCryptography/Equivalence):
- (None)
