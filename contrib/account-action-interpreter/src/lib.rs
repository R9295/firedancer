//! Build the account-action sBPF interpreter and encode its instruction stream.
//!
//! The requested compiler accepts C. The Rust project owns the builder, wire
//! format, CLI, and tests; `interpreter.c` is the on-chain implementation.

use serde::{Deserialize, Serialize};
use std::{io, path::Path};

pub const MAGIC: &[u8; 4] = b"ACI1";
pub const MAX_READ_BYTES: u32 = 512;

/// Account indices refer to the instruction's account list, including aliases.
/// Integer operands use little-endian encoding. Grow/shrink take byte deltas.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    ReadAddress {
        account: u8,
    },
    ReadLamports {
        account: u8,
    },
    ReadData {
        account: u8,
        offset: u32,
        len: u32,
    },
    ReadOwner {
        account: u8,
    },
    ReadExecutable {
        account: u8,
    },
    WriteData {
        account: u8,
        offset: u32,
        bytes: Vec<u8>,
    },
    ResizeGrow {
        account: u8,
        amount: u32,
    },
    ResizeShrink {
        account: u8,
        amount: u32,
    },
    ResizeZero {
        account: u8,
    },
    CreditLamports {
        account: u8,
        amount: u64,
    },
    DebitLamports {
        account: u8,
        amount: u64,
    },
    ZeroLamports {
        account: u8,
    },
    ReassignOwner {
        account: u8,
        owner: [u8; 32],
    },
    MarkExecutable {
        account: u8,
    },
    RemoveExecutable {
        account: u8,
    },
}

impl Action {
    pub fn opcode(&self) -> u8 {
        match self {
            Self::ReadAddress { .. } => 0,
            Self::ReadLamports { .. } => 1,
            Self::ReadData { .. } => 2,
            Self::ReadOwner { .. } => 3,
            Self::ReadExecutable { .. } => 4,
            Self::WriteData { .. } => 5,
            Self::ResizeGrow { .. } => 6,
            Self::ResizeShrink { .. } => 7,
            Self::ResizeZero { .. } => 8,
            Self::CreditLamports { .. } => 9,
            Self::DebitLamports { .. } => 10,
            Self::ZeroLamports { .. } => 11,
            Self::ReassignOwner { .. } => 12,
            Self::MarkExecutable { .. } => 13,
            Self::RemoveExecutable { .. } => 14,
        }
    }

    pub fn account(&self) -> u8 {
        match self {
            Self::ReadAddress { account }
            | Self::ReadLamports { account }
            | Self::ReadData { account, .. }
            | Self::ReadOwner { account }
            | Self::ReadExecutable { account }
            | Self::WriteData { account, .. }
            | Self::ResizeGrow { account, .. }
            | Self::ResizeShrink { account, .. }
            | Self::ResizeZero { account }
            | Self::CreditLamports { account, .. }
            | Self::DebitLamports { account, .. }
            | Self::ZeroLamports { account }
            | Self::ReassignOwner { account, .. }
            | Self::MarkExecutable { account }
            | Self::RemoveExecutable { account } => *account,
        }
    }
}

/// Encode `ACI1` followed by `(opcode:u8, account:u8, payload_len:u16, payload)`.
/// An empty stream is a successful no-op. The runtime still limits transaction
/// and instruction size; the encoder does not pack or submit transactions.
pub fn encode_actions(actions: &[Action]) -> Result<Vec<u8>, String> {
    let mut out = MAGIC.to_vec();
    for action in actions {
        let mut payload = Vec::new();
        match action {
            Action::ReadData { offset, len, .. } => {
                if *len > MAX_READ_BYTES {
                    return Err(format!(
                        "a read is limited to {MAX_READ_BYTES} bytes; split it into actions"
                    ));
                }
                payload.extend_from_slice(&offset.to_le_bytes());
                payload.extend_from_slice(&len.to_le_bytes());
            }
            Action::WriteData { offset, bytes, .. } => {
                payload.extend_from_slice(&offset.to_le_bytes());
                payload.extend_from_slice(bytes);
            }
            Action::ResizeGrow { amount, .. } | Action::ResizeShrink { amount, .. } => {
                payload.extend_from_slice(&amount.to_le_bytes());
            }
            Action::CreditLamports { amount, .. } | Action::DebitLamports { amount, .. } => {
                payload.extend_from_slice(&amount.to_le_bytes());
            }
            Action::ReassignOwner { owner, .. } => payload.extend_from_slice(owner),
            _ => {}
        }
        let len = u16::try_from(payload.len()).map_err(|_| "action payload exceeds 65535 bytes")?;
        out.extend_from_slice(&[action.opcode(), action.account()]);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&payload);
    }
    Ok(out)
}

/// Assemble with the pinned compiler's account ABI prelude, replacing its stub
/// entrypoint. Fail visibly if a compiler update changes the template shape.
pub fn interpreter_source() -> io::Result<String> {
    let (prelude, _) = solana_llvm_compiler::TEMPLATE
        .split_once("extern uint64_t entrypoint(const uint8_t *input) {")
        .ok_or_else(|| io::Error::other("compiler template entrypoint was not found"))?;
    Ok(format!("{prelude}\n{}", include_str!("interpreter.c")))
}

/// Build an sBPF v3 ELF using R9295/solana-llvm-compiler.
pub fn build_elf(output: &Path) -> io::Result<()> {
    let source = interpreter_source()?;
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = solana_llvm_compiler::codegen_sbf(&source)?;
    let result = std::fs::copy(&temporary, output).map(|_| ());
    let _ = std::fs::remove_file(&temporary);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_has_stable_wire_format() {
        let bytes = encode_actions(&[
            Action::ReadAddress { account: 2 },
            Action::WriteData {
                account: 1,
                offset: 3,
                bytes: vec![0xaa, 0xbb],
            },
            Action::DebitLamports {
                account: 0,
                amount: 0x0102030405060708,
            },
        ])
        .unwrap();
        assert_eq!(
            bytes,
            [
                b'A', b'C', b'I', b'1', 0, 2, 0, 0, 5, 1, 6, 0, 3, 0, 0, 0, 0xaa, 0xbb, 10, 0, 8,
                0, 8, 7, 6, 5, 4, 3, 2, 1,
            ]
        );
    }

    #[test]
    fn wire_and_output_bounds_are_checked_without_an_action_count_limit() {
        assert!(
            encode_actions(&[Action::ReadData {
                account: 0,
                offset: 0,
                len: 513
            }])
            .is_err()
        );
        assert!(
            encode_actions(&[Action::WriteData {
                account: 0,
                offset: 0,
                bytes: vec![0; 65532]
            }])
            .is_err()
        );
        assert!(encode_actions(&vec![Action::ReadOwner { account: 0 }; 257]).is_ok());
        assert_eq!(encode_actions(&[]).unwrap(), MAGIC);
    }
}
