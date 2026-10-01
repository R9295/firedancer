//! Execute instruction fixtures through Agave and Firedancer and compare them.

pub mod agave;
pub mod firedancer;
pub mod fuzz;

use protosol::protos::{InstrContext, InstrEffects};

/// Run a fixture through Agave and Firedancer and return the effects.
/// Panics if the two clients report different effects.
pub fn execute_instruction(context: &InstrContext) -> InstrEffects {
    compare(context, agave::execute_instruction(context))
}

/// Run a fixture through Firedancer and return `agave`, Agave's effects for the
/// same fixture. Panics if the two clients report different effects.
pub fn compare(context: &InstrContext, agave: InstrEffects) -> InstrEffects {
    let firedancer = firedancer::execute_instruction(context);
    assert_eq!(agave, firedancer, "Agave and Firedancer instruction effects differ");
    agave
}
