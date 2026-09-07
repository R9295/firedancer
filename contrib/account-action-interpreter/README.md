# Account action interpreter

A small interpreter for explicit account-action sequences in local Solana test
fixtures. One instruction contains an ordered list of actions, each selecting an
account by its index in that instruction's account list. Actions run in order,
without program-side ownership, writable, rent, or account-size policy checks.
The entrypoint returns zero whenever execution completes; the runtime can still
trap or reject the attempted changes. The interpreter does not generate sequences
or submit transactions.

This is a **Rust host project with a C on-chain interpreter** because
[`R9295/solana-llvm-compiler`](https://github.com/R9295/solana-llvm-compiler)
accepts C source, not Rust source. The dependency is pinned to commit
`68b18e19eb758c663ffe3e7dff6d9c93b3c6a247`; `Cargo.lock` pins its transitive
dependencies. The output is an **sBPF v3 ELF** using the standard aligned Solana
account-input ABI. The VM/validator executing it must enable sBPF v3.

## Build and use

From this directory, with Cargo and Solana platform-tools installed:

```sh
cargo run --locked -- build
cargo run --locked -- encode examples/actions.json artifacts/actions.bin
cargo test --locked
```

The built program is `artifacts/account_actions.so`. An alternate output path can
be passed to `build`. The compiler discovers Solana LLVM under
`~/.cache/solana/v*/platform-tools/llvm/bin`; set `SOLANA_LLVM_BIN` to that directory
explicitly if needed. The build was verified with platform-tools v1.53,
`clang-20` 20.1.7-rust-dev. After dependencies are fetched, commands can use
Cargo's `--offline` flag as well.

Load the ELF under your fixture's program ID and use `artifacts/actions.bin` as
the instruction data. Pass the accounts in the order referenced by the actions.
The example expects accounts 0 and 1 writable, account 0 owned by the fixture's
program ID with an initially empty data allocation, and enough initial lamports
to transfer one lamport while keeping persistent accounts rent-exempt. Account 1
may have any owner. No fixed program ID or transaction payer is embedded.

For use from another Rust test project, add a path dependency to this crate:

```rust
use account_action_interpreter::{Action, encode_actions};

let instruction_data = encode_actions(&[
    Action::WriteData { account: 0, offset: 0, bytes: vec![1, 2, 3] },
    Action::ReadData { account: 0, offset: 0, len: 3 },
])?;
```

To persist that example's write, the account needs at least three data bytes.
`write_data` never implicitly resizes an account.

## Actions

Every JSON object has an `action` name and `account` index. Integer operands are
unsigned; `bytes` and `owner` are JSON arrays of byte values. Grow and shrink
amounts are **deltas**, not target lengths.

| Opcode | JSON action | Other fields / binary payload | Successful read result |
| --- | --- | --- | --- |
| 0 | `read_address` | none | 32 address bytes |
| 1 | `read_lamports` | none | `u64` lamports |
| 2 | `read_data` | `offset: u32`, `len: u32` | requested bytes |
| 3 | `read_owner` | none | 32 owner bytes |
| 4 | `read_executable` | none | `u8`, 0 or 1 |
| 5 | `write_data` | `offset: u32`, `bytes: [u8...]` | none |
| 6 | `resize_grow` | `amount: u32` | none |
| 7 | `resize_shrink` | `amount: u32` | none |
| 8 | `resize_zero` | none | none |
| 9 | `credit_lamports` | `amount: u64` | none |
| 10 | `debit_lamports` | `amount: u64` | none |
| 11 | `zero_lamports` | none | none |
| 12 | `reassign_owner` | `owner: [u8; 32]` | none |
| 13 | `mark_executable` | none | unavailable observation |
| 14 | `remove_executable` | none | unavailable observation |

There are **15** listed actions. The last two are recognized requests with
explicit unavailable outcomes. Both emit observation status `2` and continue to
the next action; neither returns an instruction error:

- Loader-v3 `DeployWithMaxDataLen` cannot be invoked through sBPF CPI. The
  `mark_executable` opcode makes no CPI. Program deployment must be a separate
  top-level loader instruction.
- Changing a local executable-status copy does not persist through sBPF account
  writeback. `remove_executable` does not change that copy.
  Loader closure is a different operation and is not substituted.

These are sBPF/loader API limitations, not a claim that internal validator code
can never alter the executable field. See the
[CPI allowlist](../../src/flamenco/vm/syscall/fd_vm_syscall_cpi.c) and
[account writeback](../../src/flamenco/runtime/program/fd_bpf_loader_serialization.c).

## Instruction wire format

All integers are little-endian. No alignment or padding is required.

```text
"ACI1"                                  4-byte magic and format version
repeated until instruction data ends:
    opcode                              u8
    instruction account index           u8
    payload length                      u16
    payload                             exactly that many bytes
```

The table above specifies each payload. For `write_data`, all payload bytes after
the four-byte offset are the replacement bytes. A zero-length write is allowed.
The stream can be empty after the magic. There is no interpreter action-count
limit; the compiler prelude accepts at most 255 account-list entries.
Each read is limited to 512 bytes; split larger reads across actions. Transaction
size, compute, and log limits may impose smaller practical limits.

## Observations

Every attempted action with a parsed frame emits one `sol_log_data` slice and
sets Solana return data to the same record. Thus logs contain the sequence of
observations, while return data contains only the last observation. Validator log
limits can truncate logs. Applied writes have an empty result payload. A record
describes local execution, not runtime acceptance or transaction commit.

```text
"ACR1"                 4 bytes
step                   u32, zero-based
opcode                 u8
account index          u8
status                 u64, observation outcome (see below)
result length          u16
result bytes           0..512 bytes
```

Decode a raw record extracted from return data or a base64-decoded log slice:

```sh
cargo run --locked -- decode-result result.bin
```

The CLI prints JSON, including raw payload hex and typed read values. Addresses
and owners are displayed as hex. A malformed stream header or incomplete frame
uses opcode/account `255` when those fields are unavailable. Invalid runtime ABI
input can stop execution before any observation is produced. An empty valid
stream clears return data and emits no records.

| Observation status | Meaning |
| --- | --- |
| `0` | action applied or read performed |
| `1` | skipped: malformed or unknown action, missing account, or unsafe buffer access |
| `2` | executable action unavailable through this interpreter |

The `ACR1` layout is unchanged, but `status` no longer contains custom instruction
error codes. All statuses above are observations only. Unknown opcodes, malformed
payloads in complete frames, missing account indices, and unsafe data-buffer
accesses are skipped, and execution continues with the next frame. A malformed
stream header or incomplete frame stops interpretation because the next action
cannot be reliably decoded. These cases also return zero if the VM completes.

## Semantics and test scope

- Writes, resizes, credits, debits, zeroing lamports, and owner reassignment are
  attempted without checking ownership or writable privilege. Reassignment does
  not check whether data is zero. Runtime enforcement can occur at memory access,
  account reconciliation, or transaction finalization, depending on the runtime
  and its configuration.
- Structural decoding, account-index checks, physical data-buffer bounds, and the
  512-byte read-output bound remain. A skipped operation does not reach runtime
  policy validation, so its observation cannot demonstrate runtime rejection.
- Signer status grants no extra mutation privileges. This is a fixture program
  with no application authorization policy; use synthetic test accounts.
- Credits/debits are independent actions using wrapping unsigned 64-bit
  arithmetic. Overflow and underflow are not rejected by the interpreter. The
  runtime sees final balances, not the arithmetic intent of each action, and
  cannot be assumed to reject every wrapped calculation. For a valid instruction,
  the total must balance across unique accounts before exit. The validator enforces
  conservation, rent, and transaction-wide allocation limits. There is no
  automatic transfer, funding, or final balance repair.
- `zero_lamports` alone does not clear data or reassign ownership, and a read
  immediately afterward still observes that invocation's account data.
- Resize writes the requested logical length into the account ABI, even when it
  exceeds 10 MiB or the invocation's realloc capacity. Grow and shrink arithmetic
  also wraps as unsigned 64-bit arithmetic. Zero-filling is restricted to the
  physically supplied range, **invocation-entry data length plus 10,240 bytes**;
  it never follows an oversized logical length outside that range. Added bytes
  within that range are zero-filled, including after shrink/regrow. Shrink leaves
  the retained prefix unchanged.
- Duplicate account entries share lamports, owner, and data. Resize explicitly
  refreshes every duplicate's copied length. Effects are visible to later actions
  using any alias.
- After owner reassignment, subsequent mutations are still attempted without an
  ownership check. There is no arbitrary CPI action or change of executing
  program in this stream.
- A status-zero action log is a local observation, not proof of transaction
  commit. A later VM trap or validator post-execution check can still fail the
  instruction or transaction. Normal transaction rollback is provided by the
  validator, not this interpreter.

`tests/vm.rs` builds the ELF, loads it with `solana-sbpf` 0.22, runs the requisite
verifier, and executes it in the interpreter using synthetic aligned input and
mock observation syscalls. Tests cover every implemented opcode, aliases,
zero-filling within mapped capacity, oversized logical lengths, malformed
operands, wrapping arithmetic, skipped actions, and the two unavailable actions.
These are offline VM observation tests, not a runtime conformance oracle. They
do **not** emulate validator reconciliation, rent, transaction-wide allocation
accounting, CPI, or rollback. No network submission
or validator deployment is part of the test suite.

Files to modify: `src/interpreter.c` for execution, `src/lib.rs` for actions and
encoding, `src/main.rs` for CLI/result decoding, and `tests/vm.rs` for ELF tests.
The built ELF and encoded example are checked in under `artifacts/`. Other
generated artifacts and Cargo's target directory are ignored by Git.
