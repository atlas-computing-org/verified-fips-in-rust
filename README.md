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
- SHA-1: See `./lean/VerifiedFipsCryptography/Equivalence/SHA1`.
- AES: See `./lean/VerifiedFipsCryptography/Equivalence/AES`.

## Summary of Work Done

- Concretely showed that an equivalence between Aeneas generated Rust code and Lean specifications for SHA1 and AES can be verified, up to small bounds proofs.
- Developed a template for approaching equivalence proofs, by splitting the equivalence into 3 simpler stages that each target one particular complexity.

To explain in more detail the structure of the proofs, we split into 3 stages (`TypeEquiv`, `SemanticEquiv`, `StructuralEquiv`), and use 2 intermediary representations (`Translated`, `Structured`). 
- `Translated`: This is the representation which has the same structure as the Aeneas generated code, but we replace the Aeneas types with Lean types.
- `TypeEquiv`: In this stage, we prove an equivalence that the Aeneas generated code is equivalent to the `Translated` implementations. This stage removes the complexity of the Aeneas types, and allows us to use Lean types, which have better compiler and standard library support.
- `Structured`: This is the representation which is also identical to the Lean specification, but is slightly more structured to closer reflect the Aeneas structure. Aeneas generated code has a very rigid structure (e.g. every for loop will be factored out into a `*_loop` function).
- `SemanticEquiv`: In this stage, we prove an equivalence that the `Translated` implementation is equivalent to the `Structured` implementation. This stage is the meat of the equivalence proof, where the user must show that the core semantics of the Rust and Lean code agree with each other. Ideally, this can be shown through proving the equivalence between every sub-function of the implementations. This is why aligning the Rust and Lean code with the `Structured` representation is important.
- `StructuralEquiv`: In this stage, we prove an equivalence that the `Structured` implementation is equivalent to the orignal Lean implementation. This stage is usually just inlining functions or a few simple rewrites/unfolds to recover the original Lean structure of the code.

Each of these stages is put in their own file, will you can see in the directory structure of this project. Finally, there is a final `Equivalence.lean` file, which takes all the results and shows the full equivalence.


## Learnings 

In the process of completing this project, we've identified several areas of learning:
- Automation: By splitting up the equivalence proofs and reducing complexity, we naturally expose many opportunities for automation for each stage of equivalence. Further tools that specialize in, say, automatically proving the type-equivalence stage could be interesting to streamline the proving process for a user. (And even necessary if the scale of equivalence proofs become large.)
- Aeneas: Aeneas itself is not fully mature as a tool, and many workarounds are required to make things work. The Aeneas team seems to be rapidly developing its Lean backend support, and has thusfar been very open to help/collaboration, so we expect many of these early issues to disappear in the near future. 
- Bounds-checking: Aeneas faithfully models Rust integer types, like `u32`, whereas Lean often uses `Nat`. Thus, a significant amount of effort has to be taken to show that the Rust model will not "overflow," e.g. when adding two `u32`s or pushing to a vector. Most of these bounds are clearly trivial, and so we've justified leaving some as `sorry`s for now. However, they are a clear source of bugs, where, if not modeled correctly, we may find subtle missed assumptions.