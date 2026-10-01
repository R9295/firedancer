//! Execute instruction fixtures through Agave and Firedancer and compare them.

pub mod firedancer;
pub mod fuzz;

use protosol::protos::{InstrContext, InstrEffects};

/// Run a fixture through `solana_svm_conformance::instr::execute_instr_proto`.
/// Instruction failures are reported in `result`, not as a Rust error.
pub fn execute_agave(context: &InstrContext) -> InstrEffects {
    solana_svm_conformance::instr::execute_instr_proto(context.clone())
}

/// Run a fixture through Agave and Firedancer and return the effects.
/// Panics if the two clients report different effects.
pub fn execute_instruction(context: &InstrContext) -> InstrEffects {
    let agave = execute_agave(context);
    let firedancer = firedancer::execute_instruction(context);
    assert_eq!(agave, firedancer, "Agave and Firedancer instruction effects differ");
    agave
}
