// This module supports the use of stallone in #[cfg(test)]. Unfortunately, we can't make this
// module #[cfg(test)] since then it wouldn't be accessible by things that depend on stallone.
// This module's contents will only ever be consumed in #[cfg(test)], and they just amount to
// to a few words in .data, so it should have only a minimal impact.
use std::path::Path;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    sync::{atomic::AtomicBool, Once},
};

pub static INITIALIZE_STALLONE_FOR_TESTS: Once = Once::new();
pub static PRINT_STALLONE_LOGS_IN_TESTS: AtomicBool = AtomicBool::new(false);
thread_local! {
    pub static CONTEXT_FOR_STALLONE_LOGS_IN_TESTS: RefCell<BTreeMap<String, String>> =
        RefCell::new(BTreeMap::new());
}

#[cold]
pub fn init_once_body() {
    PRINT_STALLONE_LOGS_IN_TESTS.store(
        std::env::var("STALLONE_TEST_LOG")
            .ok()
            .filter(|x| !x.is_empty())
            .is_some(),
        std::sync::atomic::Ordering::Relaxed,
    );
    if let Some(path) = std::env::var_os("STALLONE_TEST_MASTER") {
        let _ = crate::global_state::initialize(Path::new(&path), &Default::default());
    }
}
