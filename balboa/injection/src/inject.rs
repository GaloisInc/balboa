use crate::globals::BALBOA_IS_INITIALIZED;
use std::marker::PhantomData;
use std::sync::atomic::Ordering;

#[repr(C)]
pub struct InterposeData {
    pub replacement: *const libc::c_void,
    pub original: *const libc::c_void,
}
unsafe impl Sync for InterposeData {}

extern "C" {
    fn balboa_injection_already_entered_thread_local() -> *mut u8;
}

/// A value of this type witnesses that we've already entered injection code on this thread.
///
/// When this value is dropped, it will clear the flag denoting that injection code has been run
/// on this thread.
// We want to ensure that this type is neither Send nor Sync, so we have a PhantomData containing a
// type that's neither Sync nor Send.
pub struct InjectionAlreadyEnteredGuard(PhantomData<std::rc::Rc<()>>);

impl InjectionAlreadyEnteredGuard {
    /// If the injection has already been entered, return `Some(InjectionAlreadyEnteredGuard)`,
    /// otherwise return `None`.
    pub fn enter() -> Option<Self> {
        if BALBOA_IS_INITIALIZED.load(Ordering::Acquire) {
            let ptr = unsafe { balboa_injection_already_entered_thread_local() };
            if unsafe { *ptr } == 0 {
                unsafe {
                    *ptr = 1;
                }
                Some(InjectionAlreadyEnteredGuard(PhantomData))
            } else {
                None
            }
        } else {
            None
        }
    }
}
impl Drop for InjectionAlreadyEnteredGuard {
    fn drop(&mut self) {
        let ptr = unsafe { balboa_injection_already_entered_thread_local() };
        debug_assert_eq!(1, unsafe { *ptr });
        unsafe {
            *ptr = 0;
        }
    }
}

#[cfg(target_os = "linux")]
#[cold]
pub unsafe fn find_next_function(
    name: &'static str,
    dst: &std::sync::atomic::AtomicPtr<std::ffi::c_void>,
) {
    // TODO: if dlsym() makes any dynamic library calls, we CANNOT inject over them.
    // However, we can't call the underlying dynamic library call until dlsym returns.
    // Luckily, it seems like this doesn't happen in practice.
    debug_assert_eq!(name.as_bytes().last(), Some(0).as_ref());
    let raw_ptr = libc::dlsym(
        libc::RTLD_NEXT,
        name.as_bytes().as_ptr() as *const libc::c_char,
    );
    // TODO: this is why it's important to make write() on linux hit the system call
    // directly for fd=1 and fd=2
    assert_ne!(raw_ptr, std::ptr::null_mut());
    // It's okay if we overwrite the value that's already there. All threads should be writing the
    // same value, anyways.
    dst.store(raw_ptr, std::sync::atomic::Ordering::Relaxed);
}

#[macro_export]
macro_rules! inject {
    (@INNER, $staticname:ident, $hook:expr, fn $actualns:ident :: $actual:ident ($($name:ident : $arg:ty),*) -> $rt:ty) => {
        #[cfg(not(test))]
        mod $staticname {
            use super::*;
            static _TYPE_CHECK1: unsafe extern "C" fn($($arg),*) -> $rt = $actualns :: $actual;
            static _TYPE_CHECK2: unsafe fn(unsafe extern "C" fn($($arg),*) -> $rt, $($arg),*) -> $rt = $hook;

            #[cfg(target_os="macos")]
            #[link_section="__DATA,__interpose"]
            #[used]
            static $staticname: $crate::inject::InterposeData = $crate::inject::InterposeData {
                replacement: {
                    unsafe extern "C" fn the_hook($($name : $arg),*) -> $rt {
                        $hook($actualns :: $actual, $($name),*)
                    }
                    the_hook
                } as *const std::ffi::c_void,
                original: $actualns :: $actual as *const std::ffi::c_void,
            };

            #[cfg(target_os="linux")]
            static THE_ACTUAL: std::sync::atomic::AtomicPtr<std::ffi::c_void> =
                std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

            #[cfg(target_os="linux")]
            #[cold]
            #[inline(never)]
            unsafe fn populate_the_actual() {
                $crate::inject::find_next_function(concat!(stringify!($actual), "\0"), &THE_ACTUAL);
            }

            #[cfg(target_os="linux")]
            #[no_mangle]
            pub unsafe extern "C" fn $actual($($name : $arg),*) -> $rt {
                let the_actual = loop {
                    let the_actual = THE_ACTUAL.load(std::sync::atomic::Ordering::Relaxed);
                    if the_actual.is_null() {
                        populate_the_actual();
                        continue;
                    }
                    break the_actual;
                };
                $hook(
                    std::mem::transmute::<_, unsafe extern "C" fn($($name : $arg),*) -> $rt>(the_actual),
                    $($name),*
                )
            }
        }
    };
    (
        #[switch_stacks($switch_stacks:expr)]
        $staticname:ident, $hook:expr, fn $actualns:ident :: $actual:ident ($($name:ident : $arg:ty),*) -> $rt:ty
    ) => {
        $crate::inject!(
            @INNER,
            $staticname,
            |
                the_actual_function: unsafe extern "C" fn($($arg),*) -> $rt,
                $($name : $arg),*
            | unsafe {
                static _TYPE_CHECK:
                    unsafe fn(unsafe extern "C" fn($($arg),*) -> $rt, $($arg),*) -> $rt = $hook;
                if let Some(_guard) = $crate::inject::InjectionAlreadyEnteredGuard::enter() {
                    const SWITCH_STACKS: bool = $switch_stacks;
                    if SWITCH_STACKS {
                        $crate::stacks::run_on_fresh_stack(
                            move || $hook(the_actual_function, $($name),*)
                        )
                    } else {
                        $hook(the_actual_function, $($name),*)
                    }
                } else {
                    the_actual_function($($name),*)
                }
            },
            fn $actualns::$actual ($($name : $arg),*) -> $rt
        );
    };
}
