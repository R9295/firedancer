# Interpreter test harness

Runs the interpreter's compiled SBF ELF through Agave's instruction conformance
harness, `solana_svm_conformance::instr::execute_instr_proto`: the function
behind Agave's `sol_compat_instr_execute_v1` C ABI and `test_exec_instr` binary.
It takes a `protosol::protos::InstrContext` and returns `InstrEffects`.

This project pins Agave `master` at commit
`7953e4d6984eeb9a4caf9f8b20b6dadd6cad4f8b`, as observed on 2026-10-01. That
revision uses protosol 17; the sysvar crate pins match its `dev-bins/Cargo.lock`.
Build with that revision's Rust toolchain, 1.98.1.

From the repository root, build the interpreter and run the tests:

```sh
cd interpreter
cargo build-sbf
cd ../test-harness
cargo +1.98.1 test --test interpreter -- --nocapture
```

The tests read `../interpreter/target/deploy/interpreter.so`. Set
`INTERPRETER_ELF=/absolute/path/to/interpreter.so` to override it. Rebuild the ELF
after changing the interpreter; compiling this host project only builds its Rust
action types.

`write_data_runs_in_agave` creates an eight-byte zeroed account owned by the
interpreter, supplies the executable program account and Clock/Rent sysvars,
then runs `WriteData { account: 0, offset: 2, bytes: b"hello".to_vec() }`.
It asserts successful execution, the XXH64 hash of `b"\0\0hello\0"`, unchanged
lamports/owner/executable metadata, and consumed compute units. Protosol v17
returns hashes for account data in effects, so the assertion compares that hash
against the expected bytes.

`five_interpreter_deployments_assign_cpi_then_write` loads that same ELF at
five distinct program addresses and constructs the nested chain
`P0 -> P1 -> P2 -> P3 -> P4`. Stack depth 5 includes the top-level invocation
and four nested CPIs. P0 initially owns one shared, zeroed 25-byte account.
At each level before P4, the program assigns ownership to the next deployment,
then CPIs into that deployment. P4 then writes `hello` at offsets 0, 5, 10, 15,
and 20. Agave changes an account's owner only while its data is empty or all
zero, so every handoff happens before the writes; writing first fails the first
CPI with `ModifiedProgramId` (ABI result 12). Only the shared account is
writable; all five program accounts are read-only and forwarded through the
chain.

The success assertions require exactly `hellohellohellohellohello` in the shared
account, final ownership by P4, unchanged lamports, and a non-executable data
account.

`execute_instruction` reports runtime instruction errors in `effects.result`
rather than as a Rust error, and Agave's harness panics on malformed fixtures.
Both tests explicitly require `effects.result == 0`.

## Fuzzing

The `runtime-fuzz` target gives Ziggy a structured `Vec<Action>`, the
interpreter's `Action<InterpreterIndex>`: each new owner and CPI destination
is an `InterpreterIndex` instead of a program ID. Every input byte is
normalized to an index from 0 through 4 and then translated to one of five
distinct deployments of the same ELF. Index 0 targets the entrypoint
deployment, so self-CPI, reentry, repeated programs, and arbitrary nested CPI
sequences remain available to the fuzzer. The harness does not reject actions or treat
instruction errors as harness failures; it leaves runtime validation to Agave.

Build or run the target from `test-harness`:

```sh
cargo ziggy build runtime-fuzz
cargo ziggy fuzz runtime-fuzz
```

Use `--no-afl` or `--no-honggfuzz` to select one backend. The harness loads
`../interpreter/target/deploy/interpreter.so` once at startup and restores a
fresh account fixture before each input. `INTERPRETER_ELF` overrides the ELF
path for both tests and fuzzing.

Seeds in `seeds/` are `arbitrary` encodings of that `Vec<Action>`, so changing
an `Action` field type changes their byte layout. Account indices, offsets, and
amounts are two bytes each; owners and CPI destinations are one byte.

Observed on `x86_64-unknown-linux-gnu` with Agave master `7953e4d`:

```text
WriteData passed: data hash 0x6b444591ed870d0f; consumed 721 CU
test write_data_runs_in_agave ... ok
CPI stack depth 5 passed: shared account matches hellohellohellohellohello; consumed 29130 CU
test five_interpreter_deployments_assign_cpi_then_write ... ok
test result: ok. 2 passed; 0 failed
```
