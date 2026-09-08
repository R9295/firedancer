# Interpreter test harness

Runs the interpreter's compiled SBF ELF through
`solfuzz_agave::instr::sol_compat_instr_execute_v1`. The Rust wrapper serializes
`protosol::protos::InstrContext`, calls the C ABI, and decodes `InstrEffects`.

The upstream repository has no `master` branch. This project pins commit
`267f0c42195795c5d5ab4be54b70b9ad7ca18baf` from its default branch,
`agave-v4.3.0-beta.0`, as observed on 2026-09-08. That revision re-exports the
instruction ABI from its pinned Agave dependency. `Cargo.lock` pins the complete
dependency graph, and `rust-toolchain.toml` selects upstream's Rust 1.97.1.

From the repository root, build the interpreter and run the test:

```sh
cd interpreter
cargo build-sbf
cd ../test-harness
cargo test --locked --test interpreter -- --nocapture
```

The test reads `../interpreter/target/deploy/interpreter.so`. Set
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

The ABI wrapper distinguishes an ABI failure from a runtime instruction error:
`execute_instruction` can return `Ok(effects)` with `effects.result != 0`.
The smoke test explicitly requires `effects.result == 0`.

Verified on `aarch64-apple-darwin`, using Agave's SBF bytecode interpreter path:

```text
WriteData passed: data hash 0x6b444591ed870d0f; consumed 867 CU
test write_data_runs_in_agave ... ok
test result: ok. 1 passed; 0 failed
```
