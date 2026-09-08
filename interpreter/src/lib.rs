//! Account mutation interpreter for runtime tests.
//!
//! Calldata is a Borsh-encoded `Vec<Action>`: a little-endian u32 action count,
//! followed by actions with u8 tags in declaration order. Account indices,
//! offsets, and amounts are little-endian u64 values; public keys are 32 bytes.
//! Encode it with `borsh::to_vec(&actions)`.
//!
//! Actions run in order without ownership, signer, writable, rent, balance, or
//! realloc-limit validation. Arithmetic wraps. CPI forwards every account in
//! its original order with its original signer/writable privileges, so nested
//! actions use the same indices. Include each CPI program in the outer accounts.
//!
//! This interpreter uses the aligned SBF account ABI directly. Account memory
//! accesses are deliberately unchecked; execute adversarial actions in the VM.
//! Changing the serialized executable flag does not guarantee that a runtime
//! persists it: that behavior is part of what the caller is testing.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke_unchecked,
    program_error::ProgramError,
    pubkey::Pubkey,
};
use std::{ptr, slice};

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Action {
    WriteData {
        account: u64,
        offset: u64,
        bytes: Vec<u8>,
    },
    /// Increase data length by `amount`, preserving the underlying bytes.
    ResizeGrow {
        account: u64,
        amount: u64,
    },
    /// Decrease data length by `amount`, preserving the underlying bytes.
    ResizeShrink {
        account: u64,
        amount: u64,
    },
    /// Set data length to zero. `amount` is encoded but ignored.
    ResizeZero {
        account: u64,
        amount: u64,
    },
    CreditLamports {
        account: u64,
        amount: u64,
    },
    DebitLamports {
        account: u64,
        amount: u64,
    },
    /// Set lamports to zero. `amount` is encoded but ignored.
    ZeroLamports {
        account: u64,
        amount: u64,
    },
    AssignOwner {
        account: u64,
        owner: Pubkey,
    },
    MarkExecutable {
        account: u64,
    },
    RemoveExecutable {
        account: u64,
    },
    CPI {
        address: Pubkey,
        actions: Box<Vec<Action>>,
    },
}

/// Execute Borsh-encoded actions against accounts from the aligned SBF ABI.
///
/// Like `AccountInfo::resize` and `AccountInfo::assign`, this requires account
/// storage supplied by the runtime. Ordinary `AccountInfo::new` allocations do
/// not provide the serialized headers or spare capacity used by these actions.
pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let actions = Vec::<Action>::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let mut accounts = accounts.to_vec();

    for action in actions {
        match action {
            Action::WriteData {
                account,
                offset,
                bytes,
            } => {
                let mut data = accounts[account as usize].data.borrow_mut();
                // No data-length preflight: the VM handles invalid addresses.
                unsafe {
                    ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        data.as_mut_ptr().wrapping_add(offset as usize),
                        bytes.len(),
                    );
                }
            }
            Action::ResizeGrow { account, amount } => {
                let account = &accounts[account as usize];
                let new_len = account.data_len().wrapping_add(amount as usize);
                unsafe { resize_unchecked(account, new_len) };
            }
            Action::ResizeShrink { account, amount } => {
                let account = &accounts[account as usize];
                let new_len = account.data_len().wrapping_sub(amount as usize);
                unsafe { resize_unchecked(account, new_len) };
            }
            Action::ResizeZero { account, .. } => {
                let account = &accounts[account as usize];
                unsafe { resize_unchecked(account, 0) };
            }
            Action::CreditLamports { account, amount } => {
                let mut lamports = accounts[account as usize].lamports.borrow_mut();
                **lamports = (**lamports).wrapping_add(amount);
            }
            Action::DebitLamports { account, amount } => {
                let mut lamports = accounts[account as usize].lamports.borrow_mut();
                **lamports = (**lamports).wrapping_sub(amount);
            }
            Action::ZeroLamports { account, .. } => {
                **accounts[account as usize].lamports.borrow_mut() = 0;
            }
            Action::AssignOwner { account, owner } => {
                accounts[account as usize].assign(&owner);
            }
            Action::MarkExecutable { account } => unsafe {
                set_executable(&mut accounts, account as usize, true);
            },
            Action::RemoveExecutable { account } => unsafe {
                set_executable(&mut accounts, account as usize, false);
            },
            Action::CPI { address, actions } => {
                let instruction = Instruction {
                    program_id: address,
                    accounts: accounts
                        .iter()
                        .map(|account| AccountMeta {
                            pubkey: *account.key,
                            is_signer: account.is_signer,
                            is_writable: account.is_writable,
                        })
                        .collect(),
                    data: borsh::to_vec(actions.as_ref())
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                };
                // All action-local RefCell borrows have ended before the CPI.
                invoke_unchecked(&instruction, &accounts)?;
            }
        }
    }
    Ok(())
}

/// Requires aligned SBF account storage, including its serialized length header.
/// The caller is responsible for keeping host-test accesses within allocations.
unsafe fn resize_unchecked(account: &AccountInfo, new_len: usize) {
    let mut data = account.data.borrow_mut();
    let data_ptr = data.as_mut_ptr();
    unsafe {
        // The runtime reads this header; later actions and CPI read the slice.
        data_ptr.sub(8).cast::<u64>().write(new_len as u64);
        *data = slice::from_raw_parts_mut(data_ptr, new_len);
    }
}

/// Requires the aligned SBF header immediately preceding each account key.
unsafe fn set_executable(accounts: &mut [AccountInfo], index: usize, executable: bool) {
    let key = accounts[index].key;
    unsafe {
        // Header: duplicate marker, signer, writable, executable, u32 padding.
        (key as *const Pubkey)
            .cast::<u8>()
            .cast_mut()
            .sub(5)
            .write(u8::from(executable));
    }
    // Duplicated account entries share serialized storage but copy this bool.
    for account in accounts {
        if ptr::eq(account.key, key) {
            account.executable = executable;
        }
    }
}
