use interpreter::Action;
use protosol::protos::{AcctState, InstrAcct, InstrContext, acct_state::DataRepr};
use solana_clock::Clock;
use solana_rent::Rent;
use std::{fs, path::PathBuf};
use test_harness::execute_instruction;
use xxhash_rust::xxh64::xxh64;

#[test]
fn write_data_runs_in_agave() {
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

    let program_id = vec![42; 32];
    let account_id = vec![43; 32];
    let initial_data = vec![0; 8];
    let lamports = 10_000_000;
    let actions = vec![Action::WriteData {
        account: 0,
        offset: 2,
        bytes: b"hello".to_vec(),
    }];
    let context = InstrContext {
        program_id: program_id.clone(),
        accounts: vec![
            AcctState {
                address: account_id.clone(),
                owner: program_id.clone(),
                lamports,
                data_repr: Some(DataRepr::Data(initial_data)),
                executable: false,
            },
            AcctState {
                address: program_id.clone(),
                owner: solana_sdk_ids::bpf_loader::id().to_bytes().to_vec(),
                lamports: Rent::default().minimum_balance(elf.len()),
                data_repr: Some(DataRepr::Data(elf)),
                executable: true,
            },
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
        ],
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
