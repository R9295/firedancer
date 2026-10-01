//! Structured runtime inputs with owners and CPI destinations drawn from five
//! deployments.

use arbitrary::{Arbitrary, Unstructured};
use interpreter::Action as InterpreterAction;
use protosol::protos::{AcctState, InstrAcct, InstrContext, InstrEffects, acct_state::DataRepr};
use solana_clock::Clock;
use solana_rent::Rent;
use std::{error::Error, fs, path::PathBuf};

pub const PROGRAM_IDS: [[u8; 32]; 5] = [[50; 32], [51; 32], [52; 32], [53; 32], [54; 32]];
pub const DATA_ACCOUNT_ID: [u8; 32] = [60; 32];
pub const INITIAL_DATA_LEN: usize = 25;

/// An index into `PROGRAM_IDS`. Every byte maps to one of the five deployments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterpreterIndex(u8);

impl InterpreterIndex {
    pub const fn new(index: u8) -> Self {
        Self(index % PROGRAM_IDS.len() as u8)
    }

    pub const fn get(self) -> usize {
        self.0 as usize
    }
}

impl<'a> Arbitrary<'a> for InterpreterIndex {
    fn arbitrary(input: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::new(input.arbitrary()?))
    }

    fn size_hint(depth: usize) -> (usize, Option<usize>) {
        u8::size_hint(depth)
    }
}

/// Interpreter actions with a deployment index as each new owner and CPI
/// destination. All other fields are passed through unchanged, including
/// invalid indices, offsets, sizes, and balances.
pub type Action = interpreter::Action<InterpreterIndex>;

/// Translate every owner and CPI deployment index to its program ID.
pub fn resolve(action: Action) -> InterpreterAction {
    action.map_program(|index| PROGRAM_IDS[index.get()].into())
}

pub struct RuntimeHarness {
    base_context: InstrContext,
}

impl RuntimeHarness {
    /// Load the SBF ELF once, before entering Ziggy's loop.
    pub fn from_env() -> Result<Self, Box<dyn Error>> {
        let path = std::env::var_os("INTERPRETER_ELF")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../interpreter/target/deploy/interpreter.so")
            });
        Self::new(fs::read(path)?)
    }

    /// Program 0 is the entrypoint and initially owns the shared data account.
    /// Instruction accounts are shared data at 0 and the five programs at 1..6.
    pub fn new(elf: Vec<u8>) -> Result<Self, Box<dyn Error>> {
        let mut accounts = vec![AcctState {
            address: DATA_ACCOUNT_ID.to_vec(),
            owner: PROGRAM_IDS[0].to_vec(),
            lamports: 10_000_000,
            data_repr: Some(DataRepr::Data(vec![0; INITIAL_DATA_LEN])),
            executable: false,
        }];
        accounts.extend(PROGRAM_IDS.iter().map(|id| AcctState {
            address: id.to_vec(),
            owner: solana_sdk_ids::bpf_loader::id().to_bytes().to_vec(),
            lamports: Rent::default().minimum_balance(elf.len()),
            data_repr: Some(DataRepr::Data(elf.clone())),
            executable: true,
        }));
        accounts.extend([
            AcctState {
                address: solana_sdk_ids::sysvar::clock::id().to_bytes().to_vec(),
                owner: solana_sdk_ids::sysvar::id().to_bytes().to_vec(),
                lamports: 1,
                data_repr: Some(DataRepr::Data(bincode::serialize(&Clock {
                    slot: 1,
                    ..Clock::default()
                })?)),
                executable: false,
            },
            AcctState {
                address: solana_sdk_ids::sysvar::rent::id().to_bytes().to_vec(),
                owner: solana_sdk_ids::sysvar::id().to_bytes().to_vec(),
                lamports: 1,
                data_repr: Some(DataRepr::Data(bincode::serialize(&Rent::default())?)),
                executable: false,
            },
        ]);
        Ok(Self {
            base_context: InstrContext {
                program_id: PROGRAM_IDS[0].to_vec(),
                accounts,
                instr_accounts: (0..=PROGRAM_IDS.len())
                    .map(|index| InstrAcct {
                        index: index as u32,
                        is_writable: index == 0,
                        is_signer: false,
                    })
                    .collect(),
                data: Vec::new(),
                cu_avail: 200_000,
                features: None,
            },
        })
    }

    pub fn execute(&self, actions: Vec<Action>) -> Result<InstrEffects, Box<dyn Error>> {
        // Restore every account for every input; failed executions also have
        // partial effects and must not influence the next testcase.
        let mut context = self.base_context.clone();
        let actions: Vec<InterpreterAction> = actions.into_iter().map(resolve).collect();
        context.data = borsh::to_vec(&actions)?;
        Ok(crate::execute_instruction(&context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpi(index: u8, actions: Vec<Action>) -> Action {
        Action::CPI {
            address: InterpreterIndex::new(index),
            actions: Box::new(actions),
        }
    }

    #[test]
    fn every_index_maps_to_one_of_the_five_deployments() {
        for raw_index in u8::MIN..=u8::MAX {
            let mut input = Unstructured::new(std::slice::from_ref(&raw_index));
            let index = InterpreterIndex::arbitrary(&mut input).unwrap();
            let expected_index = raw_index as usize % PROGRAM_IDS.len();
            let converted = resolve(Action::CPI {
                address: index,
                actions: Box::new(Vec::new()),
            });
            let InterpreterAction::CPI { address, actions } = converted else {
                unreachable!();
            };
            assert_eq!(address.to_bytes(), PROGRAM_IDS[expected_index]);
            assert!(actions.is_empty());
            let converted = resolve(Action::AssignOwner {
                account: 0,
                owner: index,
            });
            let InterpreterAction::AssignOwner { owner, .. } = converted else {
                unreachable!();
            };
            assert_eq!(owner.to_bytes(), PROGRAM_IDS[expected_index]);
        }
    }

    #[test]
    fn self_cpi_and_reentrant_sequences_are_preserved() {
        let converted = resolve(cpi(0, vec![cpi(0, vec![cpi(0, Vec::new())])]));
        let mut action = &converted;
        for _ in 0..3 {
            let InterpreterAction::CPI { address, actions } = action else {
                panic!("CPI nesting was changed by conversion");
            };
            assert_eq!(address.to_bytes(), PROGRAM_IDS[0]);
            action = actions.first().unwrap_or(action);
        }
    }
}
