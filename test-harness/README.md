# Interpreter test harness

Runs the interpreter's compiled SBF ELF through
`solfuzz_agave::instr::sol_compat_instr_execute_v1`. The Rust wrapper serializes
`protosol::protos::InstrContext`, calls the C ABI, and decodes `InstrEffects`.

The upstream repository has no `master` branch. This project pins commit
`267f0c42195795c5d5ab4be54b70b9ad7ca18baf` from its default branch,
`agave-v4.3.0-beta.0`, as observed on 2026-09-08. That revision re-exports the
instruction ABI from its pinned Agave dependency. `Cargo.lock` pins the complete
dependency graph, and `rust-toolchain.toml` selects upstream's Rust 1.97.1.

From the repository root, build the interpreter and run the tests:

```sh
cd interpreter
cargo build-sbf
cd ../test-harness
cargo test --locked --test interpreter -- --nocapture
```

The tests read `../interpreter/target/deploy/interpreter.so`. Set
`INTERPRETER_ELF=/absolute/path/to/interpreter.so` to override it. Rebuild the ELF
after changing the interpreter; compiling this host project only builds its Rust
action types.

`write_data_runs_in_agave` creates an eight-byte zeroed account owned by the
interpreter, supplies the executable program account and Clock/Rent sysvars,
then runs `WriteData { account: 0, offset: 2, bytes: b"hello".to_vec() }`.
It asserts successful execution, the XXH64 hash of `b"\0\0hello\0"`, unchanged
lamports/owner/executable metadata, and consumed compute units. Protosol v15
returns hashes for account data in effects, so the assertion compares that hash
against the expected bytes.

`five_interpreter_deployments_write_assign_then_cpi` loads that same ELF at
five distinct program addresses and constructs the nested chain
`P0 -> P1 -> P2 -> P3 -> P4`. Stack depth 5 includes the top-level invocation
and four nested CPIs. P0 initially owns one shared, zeroed 25-byte account.
At each level, the program writes `hello` at offset 0, 5, 10, 15, or 20,
assigns ownership to the next deployment, then CPIs into that deployment.
P4 performs the final write. Only the shared account is writable; all five
program accounts are read-only and forwarded through the chain.

The success assertions require exactly `hellohellohellohellohello` in the shared
account, final ownership by P4, unchanged lamports, and a non-executable data
account. The pinned Agave runtime currently rejects this sequence at the first
CPI with `ModifiedProgramId` (ABI result 12): changing an account's owner requires
its data to be empty or all zero, but P0 has already written `hello`. Therefore
this test currently **fails** its success assertion before P1 executes. The
fixture retains the write, assign, CPI order and the five-hello success target.

The ABI wrapper distinguishes an ABI failure from a runtime instruction error:
`execute_instruction` can return `Ok(effects)` with `effects.result != 0`.
Both tests explicitly require `effects.result == 0`.

## Fuzzing

The `runtime-fuzz` target gives Ziggy a structured `Vec<Action>`. Its action
format mirrors the interpreter's action format except that each CPI destination
is an `InterpreterIndex`. Every input byte is normalized to an index from 0
through 4 and then translated to one of five distinct deployments of the same
ELF. Index 0 targets the entrypoint deployment, so self-CPI, reentry, repeated
programs, and arbitrary nested CPI sequences remain available to the fuzzer.
The harness does not reject actions or treat instruction errors as harness
failures; it leaves runtime validation to Agave.

Build or run the target from `test-harness`:

```sh
cargo ziggy build runtime-fuzz
cargo ziggy fuzz runtime-fuzz
```

Use `--no-afl` or `--no-honggfuzz` to select one backend. The harness loads
`../interpreter/target/deploy/interpreter.so` once at startup and restores a
fresh account fixture before each input. `INTERPRETER_ELF` overrides the ELF
path for both tests and fuzzing.

Observed on `aarch64-apple-darwin`, using Agave's SBF bytecode interpreter path:

```text
WriteData passed: data hash 0x6b444591ed870d0f; consumed 867 CU
test write_data_runs_in_agave ... ok
write -> assign owner -> CPI failed (custom_err=0, remaining CU=194094)
assertion failed: result 12 != 0
test five_interpreter_deployments_write_assign_then_cpi ... FAILED
test result: FAILED. 1 passed; 1 failed
```
