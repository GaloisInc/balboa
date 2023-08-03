/// Compute the build-id of the ELF image that contains this `build_id` function.
///
/// For rust executables, that means this will return the build id of the executable. For a rust
/// `cdylib`, this will return the build id of that dynamic library.
#[cfg(target_os = "linux")]
#[cold]
pub(crate) fn build_id() -> &'static [u8] {
    // This is inspired by:
    // https://github.com/mongodb/mongo/blob/r4.2.1/src/mongo/util/stacktrace_posix.cpp and
    // https://web.archive.org/web/20200321032222/https://lists.freedesktop.org/archives/mesa-dev/2017-February/144558.html
    // TODO: this assumes 64-bit in some places.
    assert_eq!(std::mem::size_of::<*const ()>(), 8);
    struct State {
        out_base: *const u8,
        out_len: usize,
        our_base_address: u64,
    }
    #[repr(C)]
    struct ElfNhdr {
        n_namesz: libc::Elf64_Word,
        n_descsz: libc::Elf64_Word,
        n_type: libc::Elf64_Word,
    }
    fn round_to_elf_alignment(offset: libc::Elf64_Word) -> Result<usize, ()> {
        const ALIGN_TO: libc::Elf64_Word = 4;
        usize::try_from((offset + (ALIGN_TO - 1)) & !(ALIGN_TO - 1)).map_err(|_| ())
    }
    impl State {
        // TODO: have better error reporting
        fn parse_notes(&mut self, mut notes_bytes: &[u8]) -> Result<(), ()> {
            const NT_GNU_BUILD_ID: libc::Elf64_Word = 3;
            while !notes_bytes.is_empty() {
                let mut header: ElfNhdr = unsafe { std::mem::zeroed() };
                let header_bytes = notes_bytes
                    .get(0..std::mem::size_of::<ElfNhdr>())
                    .ok_or(())?;
                unsafe {
                    std::ptr::copy(
                        header_bytes.as_ptr(),
                        ((&mut header) as *mut ElfNhdr) as *mut u8,
                        std::mem::size_of::<ElfNhdr>(),
                    );
                }
                notes_bytes = notes_bytes
                    .get(std::mem::size_of::<ElfNhdr>()..)
                    .ok_or(())?;
                let note_name = notes_bytes
                    .get(0..usize::try_from(header.n_namesz).map_err(|_| ())?)
                    .ok_or(())?;
                notes_bytes = notes_bytes
                    .get(round_to_elf_alignment(header.n_namesz)?..)
                    .ok_or(())?;
                let note_desc = notes_bytes
                    .get(0..usize::try_from(header.n_descsz).map_err(|_| ())?)
                    .ok_or(())?;
                notes_bytes = notes_bytes
                    .get(round_to_elf_alignment(header.n_descsz)?..)
                    .ok_or(())?;
                if header.n_type != NT_GNU_BUILD_ID || note_name != b"GNU\0" || note_desc.is_empty()
                {
                    continue;
                }
                self.out_base = note_desc.as_ptr();
                self.out_len = note_desc.len();
            }
            Ok(())
        }
    }
    let mut dl_info: libc::Dl_info = unsafe { std::mem::zeroed() };
    if unsafe { libc::dladdr(build_id as *mut libc::c_void, &mut dl_info) } == 0 {
        // For dladdr(), non-zero means sucesss.
        return b"";
    }
    let our_base_address: u64 = unsafe { std::mem::transmute(dl_info.dli_fbase) };
    // TODO: for logging purposes, we might want to extract other info, too.
    let mut state = State {
        out_base: std::ptr::null_mut(),
        out_len: 0,
        our_base_address,
    };
    unsafe extern "C" fn callback(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        let state: *mut State = data as *mut State;
        if (*state).our_base_address != (*info).dlpi_addr {
            return 0;
        }
        // TODO: this will get the ELF path of a shared object, if we're running from a shared
        // object. It doesn't appear to work from an executable (it just returns an empty string).
        //let _ = dbg!(std::ffi::CStr::from_ptr((*info).dlpi_name).to_str());
        for phdr in
            std::slice::from_raw_parts((*info).dlpi_phdr, (*info).dlpi_phnum as usize).iter()
        {
            const PF_R: libc::Elf64_Word = 0x4;
            if (phdr.p_flags & PF_R) == 0 {
                continue;
            }
            if phdr.p_type != libc::PT_NOTE {
                continue;
            }
            let data = std::slice::from_raw_parts(
                (phdr.p_vaddr + (*info).dlpi_addr) as *const u8,
                phdr.p_memsz as usize,
            );
            // We don't care whether it has succeeded or failed.
            let _ = (*state).parse_notes(data);
        }
        0
    }
    unsafe {
        libc::dl_iterate_phdr(
            Some(callback),
            (&mut state as *mut State) as *mut libc::c_void,
        );
        if state.out_base.is_null() {
            b""
        } else {
            std::slice::from_raw_parts(state.out_base, state.out_len)
        }
    }
}

#[cfg(target_os = "macos")]
#[cold]
pub(crate) fn build_id() -> &'static [u8] {
    b""
}

#[test]
fn test_build_id() {
    use object::Object;
    let actual = build_id();
    let our_binary = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let obj = object::File::parse(our_binary.as_slice()).unwrap();
    let expected = obj.build_id().unwrap().unwrap_or(b"");
    assert_eq!(actual, expected);
}
