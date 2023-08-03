//! Parse the stallone metadata out of a compiled binary.

use crate::schema::LogRecordMetadataHash;
use object::{Endian, Object, ObjectSection};
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use stallone_common::{internal_metadata_structures::STALLONE_VERSION_2_MAGIC_NUMBER, Level};
use std::{alloc::Layout, borrow::Cow, collections::HashMap, string::FromUtf8Error};

/// The name of the section in the binary which contains the pointers to stallone metadata.
// Keep in sync with the link section in stallone/log/src/lib.rs
#[cfg(any(target_os = "linux", target_os = "macos"))]
const LINK_SECTION: &'static str = "stallonelink";

// TODO: some errors still unwrap.
#[derive(Debug, Snafu)]
pub enum LoadFromBinaryError {
    #[snafu(display("Object parse error: {}", source))]
    ObjectParseError { source: object::Error },
    #[snafu(display("Address not found {}", address))]
    AddressNotFound { address: Addr },
    #[snafu(display("Magic number mismatch. Expected {:x} got {:x}.", expected, actual))]
    MagicNumberMismatch { actual: u64, expected: u64 },
    #[snafu(display("Unable to decode string: {}", source))]
    IllegalString { source: FromUtf8Error },
    #[snafu(display("Byte value is illegal for level"))]
    IllegalLevelByte,
    #[snafu(display("Unknown log record type tag {}", tag))]
    UnknownValueTypeTag { tag: u64 },
    #[snafu(display("Backup hash has too many bits: {:x}", backup_hash))]
    BackupHashHasTooManyBits { backup_hash: u64 },
    #[snafu(display("Unknown Architecture"))]
    UnknownArchitecture,
}
impl From<object::Error> for LoadFromBinaryError {
    fn from(source: object::Error) -> Self {
        LoadFromBinaryError::ObjectParseError { source }
    }
}

/// A pointer address in the address space of the binary we are dissecting.
pub(crate) type Addr = u64;

/// A binary image reader.
pub(crate) struct ImageReader<'a> {
    endian: object::Endianness,
    pub(crate) arch: Architecture,
    sections: Vec<(object::read::Section<'a, 'a>, Option<Cow<'a, [u8]>>)>,
}
impl<'a> ImageReader<'a> {
    fn new(file: &'a object::File<'a>) -> Result<Self, LoadFromBinaryError> {
        Ok(ImageReader {
            arch: file.architecture().try_into()?,
            endian: file.endianness(),
            sections: file.sections().map(|section| (section, None)).collect(),
        })
    }

    /// Load raw bytes from the binary image.
    fn load_bytes(
        &mut self,
        mut base: Addr,
        mut dst: &mut [u8],
    ) -> Result<(), LoadFromBinaryError> {
        while !dst.is_empty() {
            // We do a linear search through the sections of binary to find which section the
            // address lives in.
            let mut made_progress = false;
            for (section, data) in self.sections.iter_mut() {
                if base < section.address() {
                    continue;
                } else if base >= section.address() + section.size() {
                    continue;
                }
                if let None = data {
                    *data = Some(section.uncompressed_data()?);
                }
                let data = data.as_ref().expect("We just set it");
                let data = if let Some(data) =
                    data.get(usize::try_from(base - section.address()).unwrap()..)
                {
                    data
                } else {
                    // section.size() doesn't neccesarily match data.len()
                    continue;
                };
                let to_take = data.len().min(dst.len());
                dst[0..to_take].copy_from_slice(&data[0..to_take]);
                base += to_take as u64;
                dst = &mut dst[to_take..];
                made_progress = true;
            }
            if !made_progress {
                return Err(LoadFromBinaryError::AddressNotFound { address: base });
            }
        }
        Ok(())
    }

    pub(crate) fn load<T: BinaryImageLoadable>(
        &mut self,
        ptr: Addr,
    ) -> Result<T, LoadFromBinaryError> {
        T::load(self, ptr)
    }

    /// Load a usize of the binary (not a usize of the host).
    fn load_usize(&mut self, base: Addr) -> Result<Addr, LoadFromBinaryError> {
        match self.arch.addr_size() {
            4 => u32::load(self, base).map(|x| x.into()),
            8 => u64::load(self, base),
            x => panic!("Unexpected addr size {}", x),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Architecture {
    X86_64,
    X86,
    // TODO: add more.
}
impl Architecture {
    pub(crate) fn addr_size(&self) -> u64 {
        match self {
            Self::X86_64 => 8,
            Self::X86 => 4,
        }
    }
    pub(crate) fn addr_layout(&self) -> Layout {
        match self {
            Architecture::X86_64 => u64::layout(*self),
            Architecture::X86 => u32::layout(*self),
        }
    }

    #[cfg(test)]
    pub(crate) fn current() -> Self {
        #[cfg(target_arch = "x86")]
        return Self::X86;
        #[cfg(target_arch = "x86_64")]
        return Self::X86_64;
        #[cfg(target_arch = "aarch64")]
        todo!("support aarch64")
    }
}
impl TryFrom<object::Architecture> for Architecture {
    type Error = LoadFromBinaryError;

    fn try_from(value: object::Architecture) -> Result<Self, Self::Error> {
        match value {
            object::Architecture::X86_64 => Ok(Self::X86_64),
            object::Architecture::I386 => Ok(Self::X86),
            _ => Err(LoadFromBinaryError::UnknownArchitecture),
        }
    }
}

/// A type that we can extract from the binary.
pub(crate) trait BinaryImageLoadable: Sized {
    fn layout(arch: Architecture) -> Layout;
    fn load(img: &mut ImageReader, ptr: Addr) -> Result<Self, LoadFromBinaryError>;
}

// We encode all bools as u8s by using a `u8` in `internal_metadata_structures.inc`. `bool` doesn't
// have a defined binary representation.
impl BinaryImageLoadable for bool {
    fn layout(arch: Architecture) -> Layout {
        u8::layout(arch)
    }

    fn load(img: &mut ImageReader, ptr: Addr) -> Result<Self, LoadFromBinaryError> {
        u8::load(img, ptr).map(|x| x != 0)
    }
}

impl BinaryImageLoadable for u8 {
    fn layout(_arch: Architecture) -> Layout {
        Layout::from_size_align(1, 1).unwrap()
    }
    fn load(img: &mut ImageReader, ptr: Addr) -> Result<Self, LoadFromBinaryError> {
        let mut buf = [0; 1];
        img.load_bytes(ptr, &mut buf)?;
        Ok(buf[0])
    }
}

impl BinaryImageLoadable for u32 {
    fn layout(_arch: Architecture) -> Layout {
        Layout::from_size_align(4, 4).unwrap()
    }
    fn load(img: &mut ImageReader, ptr: Addr) -> Result<Self, LoadFromBinaryError> {
        let mut buf = [0; 4];
        img.load_bytes(ptr, &mut buf)?;
        Ok(img.endian.read_u32_bytes(buf))
    }
}

impl BinaryImageLoadable for u64 {
    fn layout(arch: Architecture) -> Layout {
        Layout::from_size_align(
            8,
            match arch {
                Architecture::X86_64 => 8,
                Architecture::X86 => 4,
            },
        )
        .unwrap()
    }

    fn load(img: &mut ImageReader, ptr: Addr) -> Result<Self, LoadFromBinaryError> {
        let mut buf = [0; 8];
        img.load_bytes(ptr, &mut buf)?;
        Ok(img.endian.read_u64_bytes(buf))
    }
}
impl<T: BinaryImageLoadable> BinaryImageLoadable for Box<T> {
    fn layout(arch: Architecture) -> Layout {
        arch.addr_layout()
    }

    fn load(img: &mut ImageReader, ptr: Addr) -> Result<Self, LoadFromBinaryError> {
        let addr = img.load_usize(ptr)?;
        Ok(Box::new(img.load(addr)?))
    }
}
impl<T: BinaryImageLoadable> BinaryImageLoadable for Vec<T> {
    fn layout(arch: Architecture) -> Layout {
        arch.addr_layout().extend(arch.addr_layout()).unwrap().0
    }

    fn load(img: &mut ImageReader, ptr: Addr) -> Result<Self, LoadFromBinaryError> {
        let mut base = img.load_usize(ptr)?;
        // We assume that this structure is perfectly aligned (as it should be since it's just a pair
        // of words).
        let offset = img.arch.addr_size();
        let len = img.load_usize(ptr + offset)?;
        // TODO: handle this error properly
        let mut out = Vec::with_capacity(usize::try_from(len).unwrap());
        let layout = T::layout(img.arch);
        for _ in 0..len {
            out.push(img.load(base)?);
            base += layout.size() as u64;
        }
        Ok(out)
    }
}
impl BinaryImageLoadable for String {
    fn layout(arch: Architecture) -> Layout {
        Vec::<u8>::layout(arch)
    }

    fn load(img: &mut ImageReader, ptr: Addr) -> Result<Self, LoadFromBinaryError> {
        let bytes: Vec<u8> = img.load(ptr)?;
        String::from_utf8(bytes).map_err(|source| LoadFromBinaryError::IllegalString { source })
    }
}
impl BinaryImageLoadable for Level {
    fn layout(arch: Architecture) -> Layout {
        u8::layout(arch)
    }

    fn load(img: &mut ImageReader, ptr: u64) -> Result<Self, LoadFromBinaryError> {
        let byte: u8 = img.load(ptr)?;
        Level::try_from(byte).map_err(|_| LoadFromBinaryError::IllegalLevelByte)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExecutableSchema {
    // empty if it's missing
    #[serde(with = "serde_bytes")]
    pub build_id: Vec<u8>,
    pub log_record_schemas: HashMap<LogRecordMetadataHash, crate::schema::LogRecordMetadataInfo>,
}

pub fn load_binary_metadata(body: &[u8]) -> Result<ExecutableSchema, LoadFromBinaryError> {
    let file = object::File::parse(body)?;
    let mut out = ExecutableSchema {
        build_id: file.build_id()?.unwrap_or(b"").to_vec(),
        log_record_schemas: HashMap::new(),
    };
    let mut image = ImageReader::new(&file)?;
    for section in file.sections() {
        if section.name()? != LINK_SECTION {
            continue;
        }
        let data = section.uncompressed_data()?;
        let addr_size = image.arch.addr_size() as usize;
        for ptr in data.chunks(addr_size).filter(|ptr| ptr.len() == addr_size) {
            let addr = match addr_size {
                8 => file
                    .endianness()
                    .read_u64_bytes(<[u8; 8]>::try_from(ptr).unwrap()),
                4 => file
                    .endianness()
                    .read_u32_bytes(<[u8; 4]>::try_from(ptr).unwrap()) as u64,
                _ => panic!("unexpected addr size"),
            };
            if addr == 0 {
                continue;
            }
            let magic_number: u64 = image.load(addr)?;
            if magic_number != STALLONE_VERSION_2_MAGIC_NUMBER {
                return Err(LoadFromBinaryError::MagicNumberMismatch {
                    actual: magic_number,
                    expected: STALLONE_VERSION_2_MAGIC_NUMBER,
                });
            }
            let lrm: crate::schema::LogRecordMetadata = image.load(addr)?;
            out.log_record_schemas
                .insert(lrm.hash_value, lrm.log_record_metadata_info);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stallone::LoggableMetadata;

    #[allow(dead_code)]
    mod test_structures {
        use super::*;
        // We use this to exercise the type parsing functionality.
        #[derive(Debug, LoggableMetadata)]
        pub(super) struct TestStruct {
            pub(super) a: bool,
            pub(super) b: u8,
            pub(super) c: u16,
            pub(super) d: u64,
            pub(super) e: u128,
            pub(super) f: i8,
            pub(super) g: i16,
            pub(super) h: i32,
            pub(super) i: i64,
            pub(super) j: i128,
            pub(super) k: char,
            pub(super) l: String,
            pub(super) m: [(); 3],
            pub(super) n: Vec<i8>,
            pub(super) o: HashMap<u128, i8>,
        }

        #[derive(Debug, LoggableMetadata)]
        pub(super) enum TestEnum {
            Unit,
            Unit2,
            Foo(u32),
            Blarg(i64),
            SomeStructThing {
                x: [u8; 32],
                y: &'static [&'static [(&'static str, String, u8, i8)]],
                z: TestStruct,
            },
            UnitLast,
        }
    }

    #[test]
    fn test_loading_image() {
        let our_binary = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let schema = load_binary_metadata(&our_binary).unwrap();
        const TEST_MSG: &'static str = "This is a test message for test_loading_image";
        stallone::info!(
            TEST_MSG,
            number: u32 = 5,
            test_enum: test_structures::TestEnum = test_structures::TestEnum::Unit,
        );
        schema
            .log_record_schemas
            .values()
            .find(|entry| entry.message.as_str() == TEST_MSG)
            .unwrap();
        // TODO: assert that this worked by manually constructing the schema that should result.
    }

    fn test_layout<T: BinaryImageLoadable>() {
        assert_eq!(T::layout(Architecture::current()), Layout::new::<T>());
    }
    #[test]
    fn test_layouts() {
        test_layout::<u32>();
        test_layout::<u8>();
        test_layout::<u64>();
        // The inner type shouldn't affect the value.
        assert_eq!(
            Layout::new::<&'static [u8]>(),
            Vec::<u64>::layout(Architecture::current())
        );
    }
}
