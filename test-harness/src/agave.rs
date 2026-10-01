//! Execute instruction fixtures through Agave's instruction conformance harness.

use protosol::protos::{InstrContext as ProtoInstrContext, InstrEffects};
use solana_program_runtime::loaded_programs::ProgramCacheForTxBatch;
use solana_svm::conformance::{
    callback::ConformanceCallback,
    direct_mapping::direct_mapping_handle_cu_exhaustion,
    instr::{context::InstrContext, harness::execute_instr_with_callback},
    programs::{fill_program_cache_from_accounts, new_program_cache_with_builtins},
    setup::{compute_budget, program_runtime_environments, sysvar_cache_from_accounts},
};

/// Run a fixture through `solana_svm_conformance::instr::execute_instr_proto`.
/// Instruction failures are reported in `result`, not as a Rust error.
pub fn execute_instruction(context: &ProtoInstrContext) -> InstrEffects {
    solana_svm_conformance::instr::execute_instr_proto(context.clone())
}

/// Programs loaded once from a fixture's accounts.
///
/// `execute_instr_proto` loads and verifies every program account on each
/// call, which dominates per-input time. Inputs that change only instruction
/// data can reuse a fixture's programs.
pub struct Programs(ProgramCacheForTxBatch);

impl Programs {
    /// Load programs the way `execute_instr_proto` does.
    pub fn new(context: &ProtoInstrContext) -> Self {
        let context = InstrContext::from(context.clone());
        let slot = sysvar_cache_from_accounts(&context.accounts)
            .get_clock()
            .expect("fixture has no Clock sysvar")
            .slot;
        let environments = program_runtime_environments(
            &context.feature_set,
            &compute_budget(&context.feature_set),
        );
        let mut cache = new_program_cache_with_builtins(slot);
        fill_program_cache_from_accounts(
            &mut cache,
            environments.get_env_for_deployment(),
            &context.accounts,
            slot,
        );
        Self(cache)
    }

    /// `execute_instr_proto` with a fresh copy of these programs. `context`
    /// must have the same accounts and features as the loading fixture.
    /// Precompile error normalization is omitted: interpreter fixtures never
    /// invoke a precompile as the top-level program.
    pub fn execute(&self, context: &ProtoInstrContext) -> InstrEffects {
        let context = InstrContext::from(context.clone());
        let sysvar_cache = sysvar_cache_from_accounts(&context.accounts);
        let effects = execute_instr_with_callback(
            &context,
            &ConformanceCallback::default(),
            &mut self.0.clone(),
            &sysvar_cache,
        );
        let (cu_avail, has_err) = (effects.cu_avail, effects.result.is_some());
        let mut effects = InstrEffects::from(effects);
        direct_mapping_handle_cu_exhaustion(
            context.feature_set.virtual_address_space_adjustments,
            cu_avail,
            has_err,
            effects.modified_accounts.iter_mut(),
        );
        effects
    }
}
