//! Offline ELF execution tests using a synthetic aligned Solana input buffer.
//!
//! These check raw interpreter buffer writes and observation records. They do not implement
//! validator account reconciliation, rent checks, CPI, or transaction rollback.

use account_action_interpreter::{Action, build_elf, encode_actions};
use solana_sbpf::{
    aligned_memory::AlignedMemory,
    ebpf,
    elf::Executable,
    error::StableResult,
    memory_region::{AccessType, MemoryMapping, MemoryRegion},
    program::{BuiltinFunctionDefinition, BuiltinProgram, SBPFVersion},
    verifier::RequisiteVerifier,
    vm::{CallFrame, Config, ContextObject, EbpfVm, ExecutionMode},
};
use std::{
    io,
    ptr::NonNull,
    sync::{Arc, OnceLock},
};

const PROGRAM_ID: [u8; 32] = [0x42; 32];
const GROWTH_SLACK: usize = 10_240;

struct Context {
    mapping: MemoryMapping,
    remaining: u64,
    logs: Vec<Vec<u8>>,
    return_data: Vec<u8>,
}

impl ContextObject for Context {
    fn consume(&mut self, amount: u64) {
        self.remaining = self.remaining.saturating_sub(amount);
    }

    fn get_remaining(&self) -> u64 {
        self.remaining
    }

    fn active_mapping_ptr(&mut self) -> NonNull<MemoryMapping> {
        NonNull::from(&mut self.mapping)
    }
}

impl Context {
    fn copy_bytes(&self, address: u64, len: u64) -> io::Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let buffer = match self.mapping.map(AccessType::Load, address, len) {
            StableResult::Ok(buffer) => buffer,
            StableResult::Err(error) => return Err(io::Error::other(error.to_string())),
        };
        // SAFETY: the mapping checked this range; all mapped backing buffers
        // remain alive and unmoved throughout execution. We immediately copy.
        Ok(unsafe { (&*buffer.ptr()).to_vec() })
    }
}

struct LogData;

impl BuiltinFunctionDefinition<Context> for LogData {
    type Error = io::Error;

    fn rust(
        context: &mut Context,
        slices: u64,
        count: u64,
        _: u64,
        _: u64,
        _: u64,
    ) -> io::Result<u64> {
        if count > 16 {
            return Err(io::Error::other("too many log slices"));
        }
        for index in 0..count {
            let descriptor = context.copy_bytes(slices + index * 16, 16)?;
            let address = u64::from_le_bytes(descriptor[..8].try_into().unwrap());
            let len = u64::from_le_bytes(descriptor[8..].try_into().unwrap());
            let bytes = context.copy_bytes(address, len)?;
            context.logs.push(bytes);
        }
        Ok(0)
    }
}

struct SetReturnData;

impl BuiltinFunctionDefinition<Context> for SetReturnData {
    type Error = io::Error;

    fn rust(
        context: &mut Context,
        address: u64,
        len: u64,
        _: u64,
        _: u64,
        _: u64,
    ) -> io::Result<u64> {
        if len > 1024 {
            return Err(io::Error::other("return data exceeds Solana's limit"));
        }
        context.return_data = context.copy_bytes(address, len)?;
        Ok(0)
    }
}

#[derive(Clone)]
struct Account {
    address: [u8; 32],
    owner: [u8; 32],
    lamports: u64,
    data: Vec<u8>,
    writable: bool,
    executable: bool,
}

impl Account {
    fn owned(data: &[u8]) -> Self {
        Self {
            address: [0x11; 32],
            owner: PROGRAM_ID,
            lamports: 1_000_000,
            data: data.to_vec(),
            writable: true,
            executable: false,
        }
    }
}

enum Entry {
    Account(Account),
    Duplicate(u8),
}

#[derive(Clone, Copy)]
struct Layout {
    owner: usize,
    lamports: usize,
    data: usize,
    capacity: usize,
}

struct Input {
    bytes: Vec<u8>,
    layouts: Vec<Layout>,
}

impl Input {
    fn new(entries: &[Entry], instruction_data: &[u8]) -> Self {
        let mut bytes = Vec::new();
        let mut layouts = Vec::new();
        bytes.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        for entry in entries {
            match entry {
                Entry::Duplicate(index) => {
                    assert!((*index as usize) < layouts.len());
                    bytes.extend_from_slice(&[*index, 0, 0, 0, 0, 0, 0, 0]);
                    layouts.push(layouts[*index as usize]);
                }
                Entry::Account(account) => {
                    bytes.extend_from_slice(&[
                        0xff,
                        0,
                        account.writable as u8,
                        account.executable as u8,
                        0,
                        0,
                        0,
                        0,
                    ]);
                    bytes.extend_from_slice(&account.address);
                    let owner = bytes.len();
                    bytes.extend_from_slice(&account.owner);
                    let lamports = bytes.len();
                    bytes.extend_from_slice(&account.lamports.to_le_bytes());
                    bytes.extend_from_slice(&(account.data.len() as u64).to_le_bytes());
                    let data = bytes.len();
                    bytes.extend_from_slice(&account.data);
                    bytes.resize(bytes.len() + GROWTH_SLACK, 0);
                    bytes.resize(bytes.len().next_multiple_of(8), 0);
                    bytes.extend_from_slice(&u64::MAX.to_le_bytes()); // deprecated rent_epoch
                    layouts.push(Layout {
                        owner,
                        lamports,
                        data,
                        capacity: account.data.len() + GROWTH_SLACK,
                    });
                }
            }
        }
        bytes.extend_from_slice(&(instruction_data.len() as u64).to_le_bytes());
        bytes.extend_from_slice(instruction_data);
        bytes.extend_from_slice(&PROGRAM_ID);
        Self { bytes, layouts }
    }

    fn lamports(&self, account: usize) -> u64 {
        let offset = self.layouts[account].lamports;
        u64::from_le_bytes(self.bytes[offset..offset + 8].try_into().unwrap())
    }

    fn data(&self, account: usize) -> &[u8] {
        let offset = self.layouts[account].data;
        let len = usize::try_from(self.data_len(account)).unwrap();
        assert!(len <= self.layouts[account].capacity);
        &self.bytes[offset..offset + len]
    }

    fn data_len(&self, account: usize) -> u64 {
        let offset = self.layouts[account].data;
        u64::from_le_bytes(self.bytes[offset - 8..offset].try_into().unwrap())
    }

    fn physical_data(&self, account: usize) -> &[u8] {
        let layout = self.layouts[account];
        &self.bytes[layout.data..layout.data + layout.capacity]
    }
}

fn elf_bytes() -> &'static [u8] {
    static ELF: OnceLock<Vec<u8>> = OnceLock::new();
    ELF.get_or_init(|| {
        let path =
            std::env::temp_dir().join(format!("account-actions-vm-{}.so", std::process::id()));
        build_elf(&path).expect("build interpreter ELF with installed Solana LLVM");
        let bytes = std::fs::read(&path).expect("read built ELF");
        std::fs::remove_file(path).expect("remove temporary ELF");
        bytes
    })
}

struct Outcome {
    status: u64,
    logs: Vec<Vec<u8>>,
    return_data: Vec<u8>,
}

fn execute(input: &mut Input) -> Outcome {
    let config = Config {
        enabled_sbpf_versions: SBPFVersion::V3..=SBPFVersion::V3,
        ..Config::default()
    };
    let mut loader = BuiltinProgram::<Context>::new_loader(config);
    loader
        .register_definition::<LogData>("sol_log_data")
        .unwrap();
    loader
        .register_definition::<SetReturnData>("sol_set_return_data")
        .unwrap();
    let loader = Arc::new(loader);
    let executable = Executable::<Context>::from_elf(elf_bytes(), loader.clone()).unwrap();
    executable.verify::<RequisiteVerifier>().unwrap();
    assert_eq!(executable.get_sbpf_version(), SBPFVersion::V3);

    let mut stack =
        AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(executable.get_config().stack_size());
    let stack_len = stack.len();
    let mut heap = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(32 * 1024);
    let regions = vec![
        executable.get_ro_region(),
        MemoryRegion::new(&mut stack, ebpf::MM_STACK_START),
        MemoryRegion::new(&mut heap, ebpf::MM_HEAP_START),
        MemoryRegion::new(
            input.bytes.as_mut_slice() as *mut [u8],
            ebpf::MM_INPUT_START,
        ),
    ];
    // SAFETY: the executable, stack, heap, and input outlive the VM. Their
    // backing allocations are never resized or accessed during VM execution.
    let mapping =
        unsafe { MemoryMapping::new(regions, executable.get_config(), SBPFVersion::V3).unwrap() };
    let mut context = Context {
        mapping,
        remaining: 1_400_000,
        logs: Vec::new(),
        return_data: Vec::new(),
    };
    let mut frames = vec![CallFrame::default(); executable.get_config().max_call_depth];
    let status = {
        let mut vm = EbpfVm::new(loader, SBPFVersion::V3, &mut context, stack_len);
        vm.registers[1] = ebpf::MM_INPUT_START;
        let (_, result) =
            vm.execute_program(&executable, &mut ExecutionMode::Interpreted, &mut frames);
        result.unwrap()
    };
    Outcome {
        status,
        logs: context.logs,
        return_data: context.return_data,
    }
}

#[derive(Debug)]
struct Record<'a> {
    step: u32,
    opcode: u8,
    account: u8,
    status: u64,
    result: &'a [u8],
}

fn record(bytes: &[u8]) -> Record<'_> {
    assert!(bytes.len() >= 20);
    assert_eq!(&bytes[..4], b"ACR1");
    let len = u16::from_le_bytes(bytes[18..20].try_into().unwrap()) as usize;
    assert_eq!(bytes.len(), 20 + len);
    Record {
        step: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        opcode: bytes[8],
        account: bytes[9],
        status: u64::from_le_bytes(bytes[10..18].try_into().unwrap()),
        result: &bytes[20..],
    }
}

#[test]
fn reads_and_write_execute_in_order_and_report_the_last_result() {
    let actions = [
        Action::ReadAddress { account: 0 },
        Action::ReadLamports { account: 0 },
        Action::ReadOwner { account: 0 },
        Action::ReadExecutable { account: 0 },
        Action::WriteData {
            account: 0,
            offset: 1,
            bytes: vec![8, 9],
        },
        Action::ReadData {
            account: 0,
            offset: 0,
            len: 4,
        },
    ];
    let mut input = Input::new(
        &[Entry::Account(Account::owned(&[1, 2, 3, 4]))],
        &encode_actions(&actions).unwrap(),
    );
    let outcome = execute(&mut input);
    assert_eq!(outcome.status, 0);
    assert_eq!(input.data(0), &[1, 8, 9, 4]);
    assert_eq!(outcome.logs.len(), actions.len());
    assert_eq!(record(&outcome.logs[0]).result, &[0x11; 32]);
    assert_eq!(record(&outcome.logs[1]).result, &1_000_000u64.to_le_bytes());
    assert_eq!(record(&outcome.logs[2]).result, &PROGRAM_ID);
    assert_eq!(record(&outcome.logs[3]).result, &[0]);
    let last = record(&outcome.return_data);
    assert_eq!(
        (last.step, last.opcode, last.account, last.status),
        (5, 2, 0, 0)
    );
    assert_eq!(last.result, &[1, 8, 9, 4]);
}

#[test]
fn balanced_lamport_changes_update_both_accounts() {
    let first = Account::owned(&[]);
    let mut second = Account::owned(&[]);
    second.address = [0x22; 32];
    second.owner = [0x77; 32]; // Credit does not require ownership.
    let actions = [
        Action::DebitLamports {
            account: 0,
            amount: 20,
        },
        Action::CreditLamports {
            account: 1,
            amount: 20,
        },
        Action::ReadLamports { account: 1 },
    ];
    let mut input = Input::new(
        &[Entry::Account(first), Entry::Account(second)],
        &encode_actions(&actions).unwrap(),
    );
    let outcome = execute(&mut input);
    assert_eq!(outcome.status, 0);
    assert_eq!((input.lamports(0), input.lamports(1)), (999_980, 1_000_020));
    assert_eq!(
        record(&outcome.return_data).result,
        &1_000_020u64.to_le_bytes()
    );
}

#[test]
fn shrink_and_regrow_zero_new_bytes_and_duplicate_entries_share_state() {
    let actions = [
        Action::ResizeShrink {
            account: 0,
            amount: 2,
        },
        Action::ResizeGrow {
            account: 1,
            amount: 2,
        },
        Action::WriteData {
            account: 1,
            offset: 0,
            bytes: vec![9],
        },
        Action::ReadData {
            account: 0,
            offset: 0,
            len: 4,
        },
    ];
    let mut input = Input::new(
        &[
            Entry::Account(Account::owned(&[1, 2, 3, 4])),
            Entry::Duplicate(0),
        ],
        &encode_actions(&actions).unwrap(),
    );
    let outcome = execute(&mut input);
    assert_eq!(outcome.status, 0);
    assert_eq!(input.data(0), &[9, 2, 0, 0]);
    assert_eq!(input.data(1), input.data(0));
    assert_eq!(record(&outcome.return_data).result, input.data(0));
}

#[test]
fn writable_and_owner_flags_do_not_preempt_synthetic_buffer_mutations() {
    let actions = [
        Action::WriteData {
            account: 0,
            offset: 0,
            bytes: vec![9],
        },
        Action::ResizeGrow {
            account: 0,
            amount: 1,
        },
        Action::DebitLamports {
            account: 0,
            amount: 3,
        },
        Action::CreditLamports {
            account: 0,
            amount: 1,
        },
        Action::ReassignOwner {
            account: 0,
            owner: [0x55; 32],
        },
        Action::ReadOwner { account: 0 },
    ];
    for writable in [false, true] {
        for owner in [PROGRAM_ID, [0x77; 32]] {
            let mut account = Account::owned(&[1]);
            account.writable = writable;
            account.owner = owner;
            let mut input = Input::new(
                &[Entry::Account(account)],
                &encode_actions(&actions).unwrap(),
            );
            let outcome = execute(&mut input);
            assert_eq!(outcome.status, 0);
            assert_eq!(input.data(0), &[9, 0]);
            assert_eq!(input.lamports(0), 999_998);
            assert_eq!(record(&outcome.return_data).result, &[0x55; 32]);
            assert!(outcome.logs.iter().all(|bytes| record(bytes).status == 0));
        }
    }
    // This synthetic VM does not enforce account reconciliation. These asserts
    // describe the interpreter's local writes, not validator acceptance.
}

#[test]
fn malformed_streams_stop_successfully_without_partial_payload_writes() {
    let encoded = encode_actions(&[Action::WriteData {
        account: 0,
        offset: 0,
        bytes: vec![9],
    }])
    .unwrap();
    for malformed in [
        b"BAD!".to_vec(),
        b"ACI1\x05".to_vec(),
        encoded[..encoded.len() - 1].to_vec(),
    ] {
        let mut input = Input::new(&[Entry::Account(Account::owned(&[1]))], &malformed);
        let before = input.bytes.clone();
        let outcome = execute(&mut input);
        assert_eq!(outcome.status, 0);
        assert_eq!(outcome.logs.len(), 1);
        assert_eq!(record(&outcome.return_data).status, 1);
        assert_eq!(input.bytes, before);
    }
}

#[test]
fn executable_lifecycle_requests_are_unavailable_and_the_sequence_continues() {
    let actions = [
        Action::MarkExecutable { account: 0 },
        Action::RemoveExecutable { account: 0 },
        Action::ReadExecutable { account: 0 },
    ];
    for executable in [false, true] {
        let mut account = Account::owned(&[]);
        account.executable = executable;
        let mut input = Input::new(
            &[Entry::Account(account)],
            &encode_actions(&actions).unwrap(),
        );
        let outcome = execute(&mut input);
        assert_eq!(outcome.status, 0);
        assert_eq!(outcome.logs.len(), 3);
        assert_eq!(record(&outcome.logs[0]).status, 2);
        assert_eq!(record(&outcome.logs[1]).status, 2);
        let last = record(&outcome.return_data);
        assert_eq!((last.step, last.status), (2, 0));
        assert_eq!(last.result, &[executable as u8]);
    }
}

#[test]
fn owner_reassignment_with_nonzero_data_does_not_gate_subsequent_actions() {
    let actions = [
        Action::ReassignOwner {
            account: 0,
            owner: [0x55; 32],
        },
        Action::WriteData {
            account: 0,
            offset: 0,
            bytes: vec![9],
        },
        Action::ResizeZero { account: 0 },
        Action::ResizeGrow {
            account: 0,
            amount: 1,
        },
    ];
    let mut input = Input::new(
        &[Entry::Account(Account::owned(&[1]))],
        &encode_actions(&actions).unwrap(),
    );
    let outcome = execute(&mut input);
    assert_eq!(outcome.status, 0);
    assert_eq!(input.data(0), &[0]);
    let owner = input.layouts[0].owner;
    assert_eq!(&input.bytes[owner..owner + 32], &[0x55; 32]);
    assert!(outcome.logs.iter().all(|bytes| record(bytes).status == 0));
}

#[test]
fn zero_lamports_and_unsigned_arithmetic_write_raw_balances() {
    let mut destination = Account::owned(&[]);
    destination.address = [0x22; 32];
    let actions = [
        Action::ZeroLamports { account: 0 },
        Action::CreditLamports {
            account: 1,
            amount: 1_000_000,
        },
    ];
    let mut input = Input::new(
        &[
            Entry::Account(Account::owned(&[])),
            Entry::Account(destination),
        ],
        &encode_actions(&actions).unwrap(),
    );
    assert_eq!(execute(&mut input).status, 0);
    assert_eq!((input.lamports(0), input.lamports(1)), (0, 2_000_000));
    // This checks buffer writes, not runtime deletion at commit.

    for (starting_balance, action, expected) in [
        (
            0,
            Action::DebitLamports {
                account: 0,
                amount: 1,
            },
            u64::MAX,
        ),
        (
            u64::MAX,
            Action::CreditLamports {
                account: 0,
                amount: 1,
            },
            0,
        ),
    ] {
        let mut account = Account::owned(&[]);
        account.lamports = starting_balance;
        let mut input = Input::new(
            &[Entry::Account(account)],
            &encode_actions(&[action, Action::ReadLamports { account: 0 }]).unwrap(),
        );
        let outcome = execute(&mut input);
        assert_eq!(outcome.status, 0);
        assert_eq!(record(&outcome.logs[0]).status, 0);
        assert_eq!(input.lamports(0), expected);
        assert_eq!(record(&outcome.return_data).result, &expected.to_le_bytes());
    }
}

#[test]
fn logical_growth_is_recorded_beyond_slack_without_overwriting_adjacent_memory() {
    for amount in [10_240, 10_241, 10 * 1024 * 1024] {
        let action = Action::ResizeGrow { account: 0, amount };
        let mut input = Input::new(
            &[Entry::Account(Account::owned(&[7]))],
            &encode_actions(&[action]).unwrap(),
        );
        let layout = input.layouts[0];
        let physical_end = layout.data + layout.capacity;
        let following = input.bytes[physical_end..].to_vec();
        let outcome = execute(&mut input);
        assert_eq!(outcome.status, 0);
        assert_eq!(record(&outcome.return_data).status, 0);
        assert_eq!(input.data_len(0), 1 + u64::from(amount));
        assert_eq!(input.physical_data(0)[0], 7);
        assert!(input.physical_data(0)[1..].iter().all(|byte| *byte == 0));
        assert_eq!(input.bytes[physical_end..], following);
    }
}

#[test]
fn shrinking_below_zero_wraps_logical_length_and_refreshes_duplicate_entries() {
    let actions = [
        Action::ResizeShrink {
            account: 0,
            amount: 2,
        },
        Action::ResizeGrow {
            account: 1,
            amount: 2,
        },
        Action::ReadData {
            account: 0,
            offset: 0,
            len: 1,
        },
    ];
    let mut input = Input::new(
        &[Entry::Account(Account::owned(&[7])), Entry::Duplicate(0)],
        &encode_actions(&actions).unwrap(),
    );
    let outcome = execute(&mut input);
    assert_eq!(outcome.status, 0);
    assert_eq!(input.data_len(0), 1);
    assert_eq!(input.data_len(1), 1);
    assert_eq!(input.data(0), &[7]);
    assert_eq!(record(&outcome.return_data).result, &[7]);
    assert!(outcome.logs.iter().all(|bytes| record(bytes).status == 0));
}

#[test]
fn data_access_uses_physical_capacity_and_skips_unsafe_memory_ranges() {
    let actions = [
        Action::WriteData {
            account: 0,
            offset: 1,
            bytes: vec![9],
        },
        Action::ReadData {
            account: 0,
            offset: 1,
            len: 1,
        },
        Action::ResizeGrow {
            account: 0,
            amount: 10 * 1024 * 1024,
        },
        Action::WriteData {
            account: 0,
            offset: 1 + GROWTH_SLACK as u32,
            bytes: vec![99],
        },
        Action::ReadData {
            account: 0,
            offset: 1 + GROWTH_SLACK as u32,
            len: 1,
        },
        Action::ReadAddress { account: 0 },
    ];
    let mut input = Input::new(
        &[Entry::Account(Account::owned(&[7]))],
        &encode_actions(&actions).unwrap(),
    );
    let layout = input.layouts[0];
    let physical_end = layout.data + layout.capacity;
    let following = input.bytes[physical_end..].to_vec();
    let outcome = execute(&mut input);
    assert_eq!(outcome.status, 0);
    assert_eq!(outcome.logs.len(), actions.len());
    assert_eq!(record(&outcome.logs[0]).status, 0);
    assert_eq!(record(&outcome.logs[1]).result, &[9]);
    assert_eq!(record(&outcome.logs[3]).status, 1);
    assert_eq!(record(&outcome.logs[4]).status, 1);
    assert_eq!(record(&outcome.return_data).result, &[0x11; 32]);
    assert_eq!(input.bytes[physical_end..], following);
}

#[test]
fn unknown_opcode_missing_account_and_bad_payload_skip_then_continue() {
    let mut unknown = encode_actions(&[Action::ReadAddress { account: 0 }]).unwrap();
    unknown[4] = 0xff;
    let missing = encode_actions(&[Action::ReadAddress { account: 1 }]).unwrap();
    let mut bad_payload = b"ACI1".to_vec();
    bad_payload.extend_from_slice(&[0, 0, 1, 0, 42]); // read_address expects no payload
    for mut encoded in [unknown, missing, bad_payload] {
        let tail = encode_actions(&[Action::ReadLamports { account: 0 }]).unwrap();
        encoded.extend_from_slice(&tail[4..]);
        let mut input = Input::new(&[Entry::Account(Account::owned(&[7]))], &encoded);
        let before = input.bytes.clone();
        let outcome = execute(&mut input);
        assert_eq!(outcome.status, 0);
        assert_eq!(outcome.logs.len(), 2);
        assert_eq!(record(&outcome.logs[0]).status, 1);
        let last = record(&outcome.return_data);
        assert_eq!((last.step, last.status), (1, 0));
        assert_eq!(last.result, &1_000_000u64.to_le_bytes());
        assert_eq!(input.bytes, before);
    }
}

#[test]
fn oversized_observation_is_skipped_and_does_not_stop_the_sequence() {
    let mut encoded = encode_actions(&[
        Action::ReadData {
            account: 0,
            offset: 0,
            len: 512,
        },
        Action::ReadLamports { account: 0 },
    ])
    .unwrap();
    encoded[12..16].copy_from_slice(&513u32.to_le_bytes());
    let mut input = Input::new(&[Entry::Account(Account::owned(&vec![7; 513]))], &encoded);
    let outcome = execute(&mut input);
    assert_eq!(outcome.status, 0);
    assert_eq!(outcome.logs.len(), 2);
    assert_eq!(record(&outcome.logs[0]).status, 1);
    assert_eq!(
        record(&outcome.return_data).result,
        &1_000_000u64.to_le_bytes()
    );
}
