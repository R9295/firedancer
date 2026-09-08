use interpreter::{Action, process_instruction};
use solana_program::{
    account_info::AccountInfo,
    entrypoint::{MAX_PERMITTED_DATA_INCREASE, ProgramResult, deserialize},
    instruction::Instruction,
    program_error::ProgramError,
    program_stubs::{SyscallStubs, set_syscall_stubs},
    pubkey::Pubkey,
};
use std::sync::{Arc, Mutex};

// Real aligned input layout, including realloc capacity and a duplicate account.
// All host-test accesses stay inside this allocation.
fn input_buffer() -> Vec<u64> {
    let mut bytes = 3u64.to_le_bytes().to_vec();
    for (index, data) in [(1u8, &[1u8, 2, 3, 4][..]), (2, &[][..])] {
        if index == 2 {
            bytes.extend_from_slice(&[0; 8]); // Account 1 duplicates account 0.
        }
        // Deliberately non-signer, read-only, and owned by a different program.
        bytes.extend_from_slice(&[255, 0, 0, u8::from(index == 2), 0, 0, 0, 0]);
        bytes.extend_from_slice(&[index; 32]);
        bytes.extend_from_slice(&[9; 32]);
        bytes.extend_from_slice(&10u64.to_le_bytes());
        bytes.extend_from_slice(&(data.len() as u64).to_le_bytes());
        bytes.extend_from_slice(data);
        bytes.resize(bytes.len() + MAX_PERMITTED_DATA_INCREASE, 0);
        bytes.resize(bytes.len().next_multiple_of(8), 0);
        bytes.extend_from_slice(&0u64.to_le_bytes()); // Rent epoch.
    }
    bytes.extend_from_slice(&0u64.to_le_bytes()); // Empty instruction data.
    bytes.extend_from_slice(&[3; 32]); // Outer program id.
    bytes.resize(bytes.len().next_multiple_of(8), 0);
    bytes
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
        .collect()
}

fn run(accounts: &[AccountInfo], actions: &[Action]) -> ProgramResult {
    process_instruction(
        &Pubkey::new_from_array([3; 32]),
        accounts,
        &borsh::to_vec(actions).unwrap(),
    )
}

#[test]
fn data_actions_preserve_bytes_across_shrink_and_grow() {
    let mut input = input_buffer();
    let (_, accounts, _) = unsafe { deserialize(input.as_mut_ptr().cast()) };
    run(
        &accounts,
        &[
            Action::ResizeGrow {
                account: 0,
                amount: 4,
            },
            Action::WriteData {
                account: 1,
                offset: 4,
                bytes: vec![5, 6, 7, 8],
            },
            Action::ResizeShrink {
                account: 0,
                amount: 3,
            },
            Action::ResizeGrow {
                account: 1,
                amount: 3,
            },
        ],
    )
    .unwrap();
    assert_eq!(&**accounts[0].data.borrow(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(accounts[1].data_len(), 8);
    let serialized_len = unsafe {
        accounts[0]
            .data
            .borrow()
            .as_ptr()
            .sub(8)
            .cast::<u64>()
            .read()
    };
    assert_eq!(serialized_len, 8);

    run(
        &accounts,
        &[Action::ResizeZero {
            account: 1,
            amount: 6,
        }],
    )
    .unwrap();
    assert!(accounts[0].data_is_empty());
    assert!(accounts[1].data_is_empty());
    let serialized_len = unsafe {
        accounts[0]
            .data
            .borrow()
            .as_ptr()
            .sub(8)
            .cast::<u64>()
            .read()
    };
    assert_eq!(serialized_len, 0);
    run(
        &accounts,
        &[Action::ResizeGrow {
            account: 0,
            amount: 8,
        }],
    )
    .unwrap();
    assert_eq!(&**accounts[0].data.borrow(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    run(
        &accounts,
        &[Action::ResizeZero {
            account: 0,
            amount: 0,
        }],
    )
    .unwrap();
    assert!(accounts[1].data_is_empty());
}

#[test]
fn lamport_actions_use_wrapping_arithmetic_and_shared_accounts() {
    let mut input = input_buffer();
    let (_, accounts, _) = unsafe { deserialize(input.as_mut_ptr().cast()) };
    run(
        &accounts,
        &[
            Action::CreditLamports {
                account: 0,
                amount: 5,
            },
            Action::DebitLamports {
                account: 1,
                amount: 2,
            },
        ],
    )
    .unwrap();
    assert_eq!(accounts[0].lamports(), 13);
    run(
        &accounts,
        &[Action::CreditLamports {
            account: 1,
            amount: u64::MAX,
        }],
    )
    .unwrap();
    assert_eq!(accounts[0].lamports(), 12);
    run(
        &accounts,
        &[Action::DebitLamports {
            account: 0,
            amount: 13,
        }],
    )
    .unwrap();
    assert_eq!(accounts[1].lamports(), u64::MAX);
    run(
        &accounts,
        &[Action::ZeroLamports {
            account: 1,
            amount: 123,
        }],
    )
    .unwrap();
    assert_eq!(accounts[0].lamports(), 0);
}

#[derive(Default)]
struct Calls(Mutex<Vec<(Instruction, Vec<bool>)>>);

struct InterpreterStub(Arc<Calls>);

impl SyscallStubs for InterpreterStub {
    fn sol_invoke_signed(
        &self,
        instruction: &Instruction,
        accounts: &[AccountInfo],
        seeds: &[&[&[u8]]],
    ) -> ProgramResult {
        assert!(seeds.is_empty());
        assert_eq!(instruction.accounts.len(), accounts.len());
        for (meta, account) in instruction.accounts.iter().zip(accounts) {
            assert_eq!(meta.pubkey, *account.key);
            assert_eq!(meta.is_signer, account.is_signer);
            assert_eq!(meta.is_writable, account.is_writable);
        }
        self.0.0.lock().unwrap().push((
            instruction.clone(),
            accounts.iter().map(|account| account.executable).collect(),
        ));
        if instruction.program_id == Pubkey::new_from_array([255; 32]) {
            return Err(ProgramError::Custom(42));
        }
        process_instruction(&instruction.program_id, accounts, &instruction.data)
    }
}

struct RestoreStubs(Option<Box<dyn SyscallStubs>>);

impl Drop for RestoreStubs {
    fn drop(&mut self) {
        set_syscall_stubs(self.0.take().unwrap());
    }
}

#[test]
fn owner_executable_and_recursive_cpi_actions() {
    let calls = Arc::new(Calls::default());
    let _restore = RestoreStubs(Some(set_syscall_stubs(Box::new(InterpreterStub(
        calls.clone(),
    )))));
    let mut input = input_buffer();
    let (_, mut accounts, _) = unsafe { deserialize(input.as_mut_ptr().cast()) };
    // Exercise mixed privileges while keeping duplicate metadata consistent.
    accounts[0].is_signer = true;
    accounts[1].is_signer = true;
    accounts[0].is_writable = true;
    accounts[1].is_writable = true;
    let owner = Pubkey::new_from_array([7; 32]);
    let target = *accounts[2].key;
    let nested = vec![Action::CreditLamports {
        account: 1,
        amount: 4,
    }];
    let inner = vec![
        Action::WriteData {
            account: 1,
            offset: 1,
            bytes: vec![42],
        },
        Action::CPI {
            address: target,
            actions: Box::new(nested.clone()),
        },
    ];
    run(
        &accounts,
        &[
            Action::AssignOwner { account: 0, owner },
            Action::MarkExecutable { account: 1 },
            Action::CPI {
                address: target,
                actions: Box::new(inner.clone()),
            },
            Action::RemoveExecutable { account: 0 },
            Action::CPI {
                address: target,
                actions: Box::default(),
            },
            Action::DebitLamports {
                account: 0,
                amount: 1,
            },
        ],
    )
    .unwrap();
    assert_eq!(*accounts[1].owner, owner);
    assert_eq!(&**accounts[0].data.borrow(), &[1, 42, 3, 4]);
    assert_eq!(accounts[0].lamports(), 13);
    let executable = unsafe {
        (accounts[0].key as *const Pubkey)
            .cast::<u8>()
            .sub(5)
            .read()
    };
    assert_eq!(executable, 0);
    let recorded = calls.0.lock().unwrap();
    assert_eq!(recorded.len(), 3);
    assert_eq!(
        borsh::from_slice::<Vec<Action>>(&recorded[0].0.data).unwrap(),
        inner
    );
    assert_eq!(
        borsh::from_slice::<Vec<Action>>(&recorded[1].0.data).unwrap(),
        nested
    );
    assert_eq!(recorded[0].1, vec![true, true, true]);
    assert_eq!(recorded[2].1, vec![false, false, true]);
    drop(recorded);

    let result = run(
        &accounts,
        &[
            Action::CPI {
                address: Pubkey::new_from_array([255; 32]),
                actions: Box::default(),
            },
            Action::ZeroLamports {
                account: 0,
                amount: 0,
            },
        ],
    );
    assert_eq!(result, Err(ProgramError::Custom(42)));
    assert_eq!(accounts[0].lamports(), 13); // Actions after a failed CPI do not run.
}

#[test]
fn calldata_is_a_borsh_vector() {
    let actions = vec![Action::WriteData {
        account: 2,
        offset: 3,
        bytes: vec![0xaa, 0xbb],
    }];
    let mut expected = 1u32.to_le_bytes().to_vec();
    expected.push(0); // WriteData tag.
    expected.extend_from_slice(&2u64.to_le_bytes());
    expected.extend_from_slice(&3u64.to_le_bytes());
    expected.extend_from_slice(&2u32.to_le_bytes());
    expected.extend_from_slice(&[0xaa, 0xbb]);
    assert_eq!(borsh::to_vec(&actions).unwrap(), expected);
    assert_eq!(
        borsh::from_slice::<Vec<Action>>(&expected).unwrap(),
        actions
    );
    assert_eq!(run(&[], &[]), Ok(()));
    assert_eq!(
        process_instruction(&Pubkey::default(), &[], &[1, 0, 0, 0, 255]),
        Err(ProgramError::InvalidInstructionData),
    );
}
