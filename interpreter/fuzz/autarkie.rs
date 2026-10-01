use autarkie::Grammar;
use interpreter::Action as InterpreterAction;
use serde::{Deserialize, Serialize};

const PROGRAM_IDS: [[u8; 32]; 5] = [[50; 32], [51; 32], [52; 32], [53; 32], [54; 32]];

/// An owned, deliberately small program domain for Autarkie's grammar.
///
/// Keep the raw byte unconstrained so mutations retain the same modulo mapping
/// as the `arbitrary` grammar used by the differential harness.
#[derive(Clone, Copy, Debug, Deserialize, Grammar, Serialize)]
struct InterpreterIndex(u8);

/// Autarkie-local mirror of `interpreter::Action`.
///
/// This cannot use `interpreter::Action<InterpreterIndex>` directly because
/// Autarkie's derive must be applied to a type owned by this crate.
#[derive(Clone, Debug, Deserialize, Grammar, Serialize)]
enum Action {
    WriteData {
        account: u16,
        offset: u16,
        bytes: Vec<u8>,
    },
    ResizeGrow {
        account: u16,
        amount: u16,
    },
    ResizeShrink {
        account: u16,
        amount: u16,
    },
    ResizeZero {
        account: u16,
        amount: u16,
    },
    CreditLamports {
        account: u16,
        amount: u16,
    },
    DebitLamports {
        account: u16,
        amount: u16,
    },
    ZeroLamports {
        account: u16,
        amount: u16,
    },
    AssignOwner {
        account: u16,
        owner: InterpreterIndex,
    },
    MarkExecutable {
        account: u16,
    },
    RemoveExecutable {
        account: u16,
    },
    CPI {
        address: InterpreterIndex,
        actions: Box<Vec<Action>>,
    },
}

#[derive(Clone, Debug, Deserialize, Grammar, Serialize)]
struct FuzzData {
    actions: Vec<Action>,
}

impl From<Action> for InterpreterAction<InterpreterIndex> {
    fn from(action: Action) -> Self {
        match action {
            Action::WriteData {
                account,
                offset,
                bytes,
            } => Self::WriteData {
                account,
                offset,
                bytes,
            },
            Action::ResizeGrow { account, amount } => Self::ResizeGrow { account, amount },
            Action::ResizeShrink { account, amount } => Self::ResizeShrink { account, amount },
            Action::ResizeZero { account, amount } => Self::ResizeZero { account, amount },
            Action::CreditLamports { account, amount } => Self::CreditLamports { account, amount },
            Action::DebitLamports { account, amount } => Self::DebitLamports { account, amount },
            Action::ZeroLamports { account, amount } => Self::ZeroLamports { account, amount },
            Action::AssignOwner { account, owner } => Self::AssignOwner { account, owner },
            Action::MarkExecutable { account } => Self::MarkExecutable { account },
            Action::RemoveExecutable { account } => Self::RemoveExecutable { account },
            Action::CPI { address, actions } => Self::CPI {
                address,
                actions: Box::new(actions.into_iter().map(Into::into).collect()),
            },
        }
    }
}

fn resolve_actions(data: &FuzzData) -> Vec<InterpreterAction> {
    data.actions
        .iter()
        .cloned()
        .map(|action| {
            InterpreterAction::from(action)
                .map_program(|index| PROGRAM_IDS[usize::from(index.0) % PROGRAM_IDS.len()].into())
        })
        .collect()
}

autarkie::fuzz_afl!(FuzzData, |data: &FuzzData| -> Vec<u8> {
    // The AFL target consumes the interpreter's wire format, not Autarkie's
    // internal serde representation.
    borsh::to_vec(&resolve_actions(data)).expect("interpreter actions must Borsh-serialize")
});

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::BorshDeserialize;

    #[test]
    fn renderer_emits_interpreter_borsh() {
        let data = FuzzData {
            actions: vec![
                Action::AssignOwner {
                    account: 2,
                    owner: InterpreterIndex(6),
                },
                Action::CPI {
                    address: InterpreterIndex(9),
                    actions: Box::new(vec![Action::WriteData {
                        account: 3,
                        offset: 4,
                        bytes: vec![5, 6],
                    }]),
                },
            ],
        };

        let bytes = borsh::to_vec(&resolve_actions(&data)).unwrap();
        let decoded = Vec::<InterpreterAction>::try_from_slice(&bytes).unwrap();

        assert_eq!(decoded, resolve_actions(&data));
        assert_eq!(
            decoded[0],
            InterpreterAction::AssignOwner {
                account: 2,
                owner: PROGRAM_IDS[1].into(),
            }
        );
        assert!(matches!(
            &decoded[1],
            InterpreterAction::CPI { address, .. } if *address == PROGRAM_IDS[4].into()
        ));
    }
}
