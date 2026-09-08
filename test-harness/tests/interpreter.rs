use interpreter::Action;
use protosol::protos::{AcctState, InstrAcct, InstrContext, acct_state::DataRepr};
use solana_clock::Clock;
use solana_rent::Rent;
use std::{fs, path::PathBuf};
use test_harness::execute_instruction;
use xxhash_rust::xxh64::xxh64;

fn interpreter_elf() -> Vec<u8> {
    let elf_path = std::env::var_os("INTERPRETER_ELF")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../interpreter/target/deploy/interpreter.so")
        });
    let elf = fs::read(&elf_path).unwrap_or_else(|error| {
        panic!(
            "cannot read {}: {error}; build interpreter with cargo build-sbf first",
            elf_path.display()
        )
    });
    assert_eq!(&elf[..4], b"\x7fELF");
    elf
}

fn program_account(address: Vec<u8>, elf: &[u8]) -> AcctState {
    AcctState {
        address,
        owner: solana_sdk_ids::bpf_loader::id().to_bytes().to_vec(),
        lamports: Rent::default().minimum_balance(elf.len()),
        data_repr: Some(DataRepr::Data(elf.to_vec())),
        executable: true,
    }
}

fn sysvar_accounts() -> [AcctState; 2] {
    [
        AcctState {
            address: solana_sdk_ids::sysvar::clock::id().to_bytes().to_vec(),
            owner: solana_sdk_ids::sysvar::id().to_bytes().to_vec(),
            lamports: 1,
            data_repr: Some(DataRepr::Data(
                bincode::serialize(&Clock {
                    slot: 1,
                    ..Clock::default()
                })
                .unwrap(),
            )),
            executable: false,
        },
        AcctState {
            address: solana_sdk_ids::sysvar::rent::id().to_bytes().to_vec(),
            owner: solana_sdk_ids::sysvar::id().to_bytes().to_vec(),
            lamports: 1,
            data_repr: Some(DataRepr::Data(
                bincode::serialize(&Rent::default()).unwrap(),
            )),
            executable: false,
        },
    ]
}

#[test]
fn write_data_runs_in_agave() {
    let elf = interpreter_elf();
    let program_id = vec![42; 32];
    let account_id = vec![43; 32];
    let initial_data = vec![0; 8];
    let lamports = 10_000_000;
    let actions = vec![Action::WriteData {
        account: 0,
        offset: 2,
        bytes: b"hello".to_vec(),
    }];
    let mut accounts = vec![
        AcctState {
            address: account_id.clone(),
            owner: program_id.clone(),
            lamports,
            data_repr: Some(DataRepr::Data(initial_data)),
            executable: false,
        },
        program_account(program_id.clone(), &elf),
    ];
    accounts.extend(sysvar_accounts());
    let context = InstrContext {
        program_id: program_id.clone(),
        accounts,
        instr_accounts: vec![InstrAcct {
            index: 0,
            is_writable: true,
            is_signer: false,
        }],
        data: borsh::to_vec(&actions).unwrap(),
        cu_avail: 200_000,
        features: None,
    };

    let effects = execute_instruction(&context).expect("compatibility API failed");
    assert_eq!(effects.result, 0, "instruction failed: {effects:?}");
    let account = effects
        .modified_accounts
        .iter()
        .find(|account| account.address == account_id)
        .expect("target account missing from instruction effects");
    // Protosol v15 effects carry XXH64(seed=0), including the untouched bytes.
    let expected_hash = xxh64(b"\0\0hello\0", 0);
    assert_eq!(account.data_repr, Some(DataRepr::DataHash(expected_hash)));
    assert_eq!(account.lamports, lamports);
    assert_eq!(account.owner, program_id);
    assert!(!account.executable);
    assert!(
        effects.cu_avail < context.cu_avail,
        "the interpreter must consume compute units"
    );
    println!(
        "WriteData passed: data hash {expected_hash:#018x}; consumed {} CU",
        context.cu_avail - effects.cu_avail
    );
}

#[test]
fn five_interpreter_deployments_write_assign_then_cpi() {
    // Stack depth counts the top-level invocation: P0 -> P1 -> P2 -> P3 -> P4.
    // Each deployment writes, assigns ownership to the next program, then CPIs.
    const DEPTH: usize = 5;
    let elf = interpreter_elf();
    let program_ids: Vec<_> = (0..DEPTH).map(|i| vec![50 + i as u8; 32]).collect();
    let account_id = vec![60; 32];
    let owner = program_ids[0].clone();
    let lamports = 10_000_000;
    let expected_data = b"hellohellohellohellohello";

    // Instruction account 0 is shared data; 1..6 are executable programs.
    // The interpreter preserves this ordering at every CPI level.
    let mut accounts = vec![AcctState {
        address: account_id.clone(),
        owner: owner.clone(),
        lamports,
        data_repr: Some(DataRepr::Data(vec![0; expected_data.len()])),
        executable: false,
    }];
    accounts.extend(
        program_ids
            .iter()
            .map(|id| program_account(id.clone(), &elf)),
    );
    accounts.extend(sysvar_accounts());

    // Build nested calldata from the deepest invocation back to the first.
    let mut actions = Vec::new();
    for level in (0..DEPTH).rev() {
        let write = Action::WriteData {
            account: 0,
            offset: (level * b"hello".len()) as u64,
            bytes: b"hello".to_vec(),
        };
        let mut current = vec![write];
        if level + 1 < DEPTH {
            current.push(Action::AssignOwner {
                account: 0,
                owner: program_ids[level + 1].as_slice().try_into().unwrap(),
            });
            current.push(Action::CPI {
                address: program_ids[level + 1].as_slice().try_into().unwrap(),
                actions: Box::new(actions),
            });
        }
        actions = current;
    }

    let context = InstrContext {
        program_id: program_ids[0].clone(),
        accounts,
        instr_accounts: (0..=DEPTH)
            .map(|index| InstrAcct {
                index: index as u32,
                is_writable: index == 0,
                is_signer: false,
            })
            .collect(),
        data: borsh::to_vec(&actions).unwrap(),
        cu_avail: 200_000,
        features: None,
    };

    let effects = execute_instruction(&context).expect("compatibility API failed");
    assert_eq!(
        effects.result, 0,
        "write -> assign owner -> CPI failed (custom_err={}, remaining CU={})",
        effects.custom_err, effects.cu_avail,
    );
    let account = effects
        .modified_accounts
        .iter()
        .find(|account| account.address == account_id)
        .expect("shared data account missing from instruction effects");
    assert_eq!(
        account.data_repr,
        Some(DataRepr::DataHash(xxh64(expected_data, 0))),
        "the shared account must contain exactly five concatenated hellos",
    );
    assert_eq!(account.owner, program_ids[DEPTH - 1]);
    assert_eq!(account.lamports, lamports);
    assert!(!account.executable);
    assert!(effects.cu_avail < context.cu_avail);
    println!(
        "CPI stack depth {DEPTH} passed: shared account matches {}; consumed {} CU",
        std::str::from_utf8(expected_data).unwrap(),
        context.cu_avail - effects.cu_avail,
    );
}
