//! Execute instruction fixtures through solfuzz-agave's protobuf C ABI.

pub mod fuzz;

use prost::Message;
use protosol::protos::{InstrContext, InstrEffects};
use std::{error::Error, io, sync::Mutex};

// The compatibility library has process-global lifecycle state.
static SESSION: Mutex<()> = Mutex::new(());

struct Session;

impl Drop for Session {
    fn drop(&mut self) {
        unsafe { solfuzz_agave::sol_compat_fini() };
    }
}

/// Serialize a fixture, call `sol_compat_instr_execute_v1`, and decode its effects.
/// A successful ABI call can still report an instruction failure in `result`.
pub fn execute_instruction(context: &InstrContext) -> Result<InstrEffects, Box<dyn Error>> {
    let _lock = SESSION
        .lock()
        .map_err(|_| io::Error::other("session mutex poisoned"))?;
    unsafe { solfuzz_agave::sol_compat_init(0) };
    let _session = Session;

    let mut input = context.encode_to_vec();
    // Include space for all input accounts plus reallocations and protobuf framing.
    let mut output = vec![0; input.len() + context.accounts.len() * 10_240 + 65_536];
    let mut output_len = output.len() as u64;
    let status = unsafe {
        solfuzz_agave::instr::sol_compat_instr_execute_v1(
            output.as_mut_ptr(),
            &mut output_len,
            input.as_mut_ptr(),
            input.len() as u64,
        )
    };
    if status != 1 {
        return Err(io::Error::other(format!("compatibility API returned {status}")).into());
    }
    if output_len > output.len() as u64 {
        return Err(io::Error::other("compatibility API returned an invalid output length").into());
    }
    Ok(InstrEffects::decode(&output[..output_len as usize])?)
}
