//! Execute instruction fixtures through Firedancer's `sol_compat` C ABI.
//!
//! `build.rs` builds `libfd_exec_sol_compat.so`. It is loaded with `dlopen`
//! because Agave's harness exports the same `sol_compat_*` symbol names.

use libloading::Library;
use prost::Message;
use protosol::protos::{FeatureSet, InstrContext, InstrEffects};
use std::{
    ffi::c_int,
    slice,
    sync::{LazyLock, mpsc},
    thread,
};

const PATH: &str = env!("FD_SOL_COMPAT_LIB");

// Effects carry account data hashes, not data.
const OUTPUT_MAX: usize = 1 << 20;

type Execute = unsafe extern "C" fn(*mut u8, *mut u64, *const u8, u64) -> c_int;
type Request = (Vec<u8>, mpsc::Sender<Option<Vec<u8>>>);

/// `sol_compat_features_t` from `fd_sol_compat.h`.
#[repr(C)]
struct Features {
    struct_size: u64,
    hardcoded_features: *const u64,
    hardcoded_features_cnt: u64,
    supported_features: *const u64,
    supported_feature_cnt: u64,
}

static LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    unsafe { Library::new(PATH) }.unwrap_or_else(|error| panic!("cannot load {PATH}: {error}"))
});

fn symbol<T: Copy>(name: &str) -> T {
    *unsafe { LIBRARY.get::<T>(name) }.unwrap_or_else(|error| panic!("{PATH}: {error}"))
}

// sol_compat keeps global and thread-local state, so one long-lived thread
// initializes it and runs every input. It starts on first use: a fork, such
// as AFL's forkserver, would not copy an existing thread.
static SESSION: LazyLock<mpsc::Sender<Request>> = LazyLock::new(|| {
    let init: unsafe extern "C" fn(c_int) = symbol("sol_compat_init");
    let execute: Execute = symbol("sol_compat_instr_execute_v1");
    let (requests, inputs) = mpsc::channel::<Request>();
    thread::Builder::new()
        .name("firedancer".into())
        // Firedancer's main thread and tiles get 8 MiB stacks.
        .stack_size(8 << 20)
        .spawn(move || {
            unsafe { init(0) };
            for (input, reply) in inputs {
                let mut output = vec![0; OUTPUT_MAX];
                let mut output_len = OUTPUT_MAX as u64;
                let status = unsafe {
                    execute(
                        output.as_mut_ptr(),
                        &mut output_len,
                        input.as_ptr(),
                        input.len() as u64,
                    )
                };
                output.truncate(output_len as usize);
                let _ = reply.send((status == 1).then_some(output));
            }
        })
        .expect("could not start the Firedancer thread");
    requests
});

/// Features activated on every cluster. Firedancer treats them as hardcoded and
/// has removed their inactive behavior, so fixtures compared with Agave should
/// activate them.
pub fn hardcoded_features() -> FeatureSet {
    let get_features: unsafe extern "C" fn() -> *const Features =
        symbol("sol_compat_get_features_v1");
    let features = unsafe { &*get_features() };
    FeatureSet {
        features: unsafe {
            slice::from_raw_parts(
                features.hardcoded_features,
                features.hardcoded_features_cnt as usize,
            )
        }
        .to_vec(),
    }
}

/// Run a fixture through `sol_compat_instr_execute_v1`. Firedancer requires
/// `features`, and reports instruction failures in `result`.
pub fn execute_instruction(context: &InstrContext) -> InstrEffects {
    let (reply, output) = mpsc::channel();
    SESSION
        .send((context.encode_to_vec(), reply))
        .expect("the Firedancer thread exited");
    let output = output
        .recv()
        .expect("the Firedancer thread exited")
        .expect("sol_compat_instr_execute_v1 failed");
    InstrEffects::decode(output.as_slice()).expect("Firedancer returned invalid InstrEffects")
}
