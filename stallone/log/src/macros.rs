#[doc(hidden)]
#[inline(always)]
pub fn internal_ensure_header_lives(
    ptr: &'static &'static crate::internal_metadata_structures::LogRecordMetadata,
) {
    // We currently do this to work-around https://github.com/rust-lang/rust/issues/47384
    // It also helps with release builds where the linker will garbage collect the stallone sections
    // if they're not accessed.
    unsafe {
        std::ptr::read_volatile(ptr);
    }
}

// This should be async-signal safe.
// TODO: how should we go about assuring that LoggableMetadata functions are async-signal safe?
#[doc(hidden)]
#[macro_export]
macro_rules! log {
    ($lvl:expr, $msg:expr $(, $(#[context($ctx:expr)])? $k:ident : $ty:ty = $v:expr)*) => {{
        const METADATA_INFO: $crate::internal_metadata_structures::LogRecordMetadataInfo = $crate::internal_metadata_structures::LogRecordMetadataInfo {
            level: $lvl,
            message: $msg,
            file: file!(),
            module_path: module_path!(),
            line: line!() as u64,
            column: column!() as u64,
            cargo_pkg_version: env!("CARGO_PKG_VERSION"),
            fields: &[
                $(
                    $crate::internal_metadata_structures::LogRecordMetadataField {
                        name: stringify!($k),
                        type_id: &<$ty as $crate::LoggableMetadata>::TYPE_ID,
                        is_context: {
                            let mut is_context = false;
                            is_context = false; // silence mutability warning
                            $(is_context = $ctx;)?
                            is_context as u8
                        },
                    },
                )*
            ],
        };
        const HASH_VALUE: $crate::internal_metadata_structures::LogRecordMetadataHash = METADATA_INFO.log_record_metadata_hash();
        #[used]
        // Keep in sync with the link section in stallone/parsing/src/load_from_binary.rs
        #[cfg_attr(target_os = "linux", link_section = "stallonelink")]
        #[cfg_attr(target_os = "macos", link_section = "__DATA,stallonelink")]
        static _METADATA: &'static $crate::internal_metadata_structures::LogRecordMetadata = &$crate::internal_metadata_structures::LogRecordMetadata {
            magic_number: $crate::internal_metadata_structures::STALLONE_VERSION_2_MAGIC_NUMBER,
            hash_value: HASH_VALUE,
            log_record_metadata_info: METADATA_INFO,
        };
        // TODO: on Linux only, putting this inside the closure below causes the static to not be
        // emitted in a special section. Why?
        $crate::internal_ensure_header_lives(&_METADATA);
        // TODO: should we compute these even if stallone is disabled?
        $(
            let $k : &$ty = &$v;
        )*
        // We need to put any #[cfg(test)] stuff _inside_ the macro. Otherwise, the code will only
        // be emitted when the stallone crate is being tested.
        #[cfg(test)]
        {
            $crate::stallone_in_tests::INITIALIZE_STALLONE_FOR_TESTS.call_once($crate::stallone_in_tests::init_once_body);
        }
        $crate::stallone_thread_local(#[inline(always)] |tl| {
            let the_size_arr = [$(<$ty as $crate::LoggableMetadata>::log_size($k)),*];
            let the_size = the_size_arr.iter().sum();
            let mut the_size_index = 0;
            tl.write_record($lvl, HASH_VALUE, the_size, #[inline(always)] |mut the_buf| {
                $(
                    let the_item_size = the_size_arr[the_size_index];
                    the_size_index += 1;
                    <$ty as $crate::LoggableMetadata>::log_serialize(
                        $k,
                        &mut the_buf[0..the_item_size],
                    );
                    the_buf = &mut the_buf[the_item_size..];
                )*
                let _ = the_size_index; // silence warning
                let _ = the_buf; // silence warning
            });
        });
        #[cfg(test)]
        {
            if $crate::stallone_in_tests::PRINT_STALLONE_LOGS_IN_TESTS.load(
                std::sync::atomic::Ordering::Relaxed,
            ) {
                use std::io::Write;
                let stderr = std::io::stderr();
                let mut handle = stderr.lock();
                write!(
                    &mut handle,
                    "[{:?}] {:?} {}:{}:{} {}\n",
                    $lvl,
                    std::time::SystemTime::now(),
                    file!(),
                    line!(),
                    column!(),
                    $msg,
                ).unwrap();
                $(
                    let mut is_context = false;
                    is_context = false; // silence mutability warning
                    $(is_context = $ctx;)?
                    let to_print_raw = format!("{} = {:#?}", stringify!($k), $k);
                    let mut to_print = String::new();
                    for line in to_print_raw.lines() {
                        to_print.push_str("    ");
                        to_print.push_str(line);
                        to_print.push('\n');
                    }
                    if is_context {
                        $crate::stallone_in_tests::CONTEXT_FOR_STALLONE_LOGS_IN_TESTS.with(|ctx| {
                            ctx.borrow_mut().insert(stringify!($k).to_string(), to_print);
                        });
                    } else {
                        write!(&mut handle, "{}", to_print).unwrap();
                    }
                )*
                $crate::stallone_in_tests::CONTEXT_FOR_STALLONE_LOGS_IN_TESTS.with(|ctx| {
                    for v in ctx.borrow().values() {
                        write!(&mut handle, "{}", v).unwrap();
                    }
                });
            }
        }
    }};
    ($lvl:expr, $msg:expr , $($(#[context($ctx:expr)])? $k:ident : $ty:ty = $v:expr,)*) => {
        $crate::log!($lvl, $msg $(, $(#[context($ctx)])? $k:$ty=$v)*);
    };
}

/// Log information at the Error level.
/// # Example
/// ```
/// let name = "Joe".to_string();
/// stallone::error!(
///     "here is my error message",
///     some_number: u32 = 536,
///     the_name: String = name,
///     the_name_referenceed: &str = name.as_str(),
/// );
/// std::mem::drop(name); // The stallone macros do not take ownership of any values.
/// ```
#[macro_export]
macro_rules! error {
    ($($arg:tt)+) => (
        $crate::log!($crate::Level::Error, $($arg)+);
    )
}

/// Log information at the Warn level.
/// # Example
/// ```
/// let name = "Joe".to_string();
/// stallone::warn!(
///     "here is my warning message",
///     some_number: u32 = 536,
///     the_name: String = name,
///     the_name_referenceed: &str = name.as_str(),
/// );
/// std::mem::drop(name); // The stallone macros do not take ownership of any values.
/// ```
#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => (
        $crate::log!($crate::Level::Warn, $($arg)+);
    )
}

/// Log information at the Info level.
/// # Example
/// ```
/// let name = "Joe".to_string();
/// stallone::info!(
///     "here is my informational message",
///     some_number: u32 = 536,
///     the_name: String = name,
///     the_name_referenceed: &str = name.as_str(),
/// );
/// std::mem::drop(name); // The stallone macros do not take ownership of any values.
/// ```
#[macro_export]
macro_rules! info {
    ($($arg:tt)+) => (
        $crate::log!($crate::Level::Info, $($arg)+);
    )
}

/// Log information at the Debug level.
/// # Example
/// ```
/// let name = "Joe".to_string();
/// stallone::debug!(
///     "here is my debug message",
///     some_number: u32 = 536,
///     the_name: String = name,
///     the_name_referenceed: &str = name.as_str(),
/// );
/// std::mem::drop(name); // The stallone macros do not take ownership of any values.
/// ```
#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) => (
        $crate::log!($crate::Level::Debug, $($arg)+);
    )
}

/// Like `std::assert!`, but instead of panicking, log about it.
/// # Example
/// ```
/// stallone::warn_assert!(true);
/// ```
// TODO: add option to pass additional info here.
#[macro_export]
macro_rules! warn_assert {
    ($cond:expr) => {
        if !$cond {
            $crate::error!(concat!("warn_assert!(", stringify!($cond), ") failed",),);
        }
    };
}

/// Like `std::assert_eq!`, but instead of panicking, log about it.
/// # Example
/// ```
/// stallone::warn_assert_eq!(one: u32 = 1, five_over_five: u32 = 5/5);
/// ```
#[macro_export]
macro_rules! warn_assert_eq {
    ($lhsname:ident : $lhsty:ty = $lhs:expr, $rhsname:ident : $rhsty:ty = $rhs:expr $(,)?) => {{
        let cond = $lhs != $rhs;
        if cond {
            $crate::error!(
                concat!(
                    "warn_assert_eq!(",
                    stringify!($lhs),
                    ", ",
                    stringify!($rhs),
                    ") failed",
                ),
                $lhsname: $lhsty = $lhs,
                $rhsname: $rhsty = $rhs,
            );
        }
        cond
    }};
}

#[macro_export]
macro_rules! warn_assert_ne {
    ($lhsname:ident : $lhsty:ty = $lhs:expr, $rhsname:ident : $rhsty:ty = $rhs:expr $(,)?) => {
        if $lhs == $rhs {
            $crate::error!(
                concat!(
                    "warn_assert_ne!(",
                    stringify!($lhs),
                    ", ",
                    stringify!($rhs),
                    ") failed",
                ),
                $lhsname: $lhsty = $lhs,
                $rhsname: $rhsty = $rhs,
            );
        }
    };
}
