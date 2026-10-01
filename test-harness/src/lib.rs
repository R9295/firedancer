//! Execute instruction fixtures through Agave's instruction conformance harness.

pub mod fuzz;

use protosol::protos::{InstrContext, InstrEffects};

/// Run a fixture through `solana_svm_conformance::instr::execute_instr_proto`.
/// Instruction failures are reported in `result`, not as a Rust error.
pub fn execute_instruction(context: &InstrContext) -> InstrEffects {
    solana_svm_conformance::instr::execute_instr_proto(context.clone())
}
