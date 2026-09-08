use arbitrary::{Arbitrary, Unstructured};
use test_harness::fuzz::{Action, RuntimeHarness};

fn main() {
    let harness = RuntimeHarness::from_env().expect("could not load the interpreter ELF");
    ziggy::fuzz!(|data: &[u8]| {
        let Ok(actions) = Arbitrary::arbitrary(&mut Unstructured::new(data)) else {
            return;
        };
        let effects = harness.execute(actions).expect("compatibility API failed");
        println!("{:#?}", effects);
        // Instruction errors are runtime outcomes. Panics, crashes, and ABI
        // failures remain visible to Ziggy; no action sequence is filtered.
        std::hint::black_box(effects);
    });
}
