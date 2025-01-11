import Lake
open Lake DSL

-- require mathlib from git "https://github.com/leanprover-community/mathlib4.git"
-- require mathlib from git "https://github.com/leanprover-community/mathlib4" @ "v4.12.0"
-- require assertCmd from git "https://github.com/pnwamk/lean4-assert-command" @ "main"

require base from "./aeneas/backends/lean"

package «verified_fips_cryptography» where
  -- Settings applied to both builds and interactive editing
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩ -- pretty-prints `fun a ↦ b`
  ]
  -- add any additional package configuration options here

@[default_target]
lean_lib «VerifiedFipsCryptography» where
  -- add any library configuration options here
