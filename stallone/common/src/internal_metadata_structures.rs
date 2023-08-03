//! Structures which are used by stallone to define metadata of log statements.

// See internal_metadata_structures.inc for more info. This file generates "borrowed" versions of
// these structures.

use super::Level;
use crate::const_siphash::SipHash24;

// This shouldn't be used at runtime.
/// This is the siphash key which is used to compute the hashes of `LogRecordMetadataInfo`
const SCHEMA_HASH_KEY: u128 = 0x6a0cc42630107d473f1947d1db982b24;
/// This magic number is included with log record metadata entries to help the parser identify
/// which stallone metadata format (in case we ever change the versions) is being used. It also
/// helps to distinguish it from other random data that we might parse on accident.
///
/// This value is stored in the `magic_number` field of `LogRecordMetadata`
pub const STALLONE_VERSION_2_MAGIC_NUMBER: u64 = 0x6bd0fbdabeccd270;

pub type EnumDiscriminant = u8;

// Since we can't have "const fn" in traits, we manually specify these types as an alternative.
struct HashNothing<T>(T);
impl<T> HashNothing<T> {
    #[cold]
    const fn hash(&self, state: SipHash24) -> SipHash24 {
        state
    }
}
struct HashU8(u8);
impl HashU8 {
    #[cold]
    const fn hash(&self, state: SipHash24) -> SipHash24 {
        state.update_u64(self.0 as u64)
    }
}
struct HashU64Ref<'a>(&'a u64);
impl<'a> HashU64Ref<'a> {
    #[cold]
    const fn hash(&self, state: SipHash24) -> SipHash24 {
        state.update_u64(*self.0)
    }
}
struct HashU64(u64);
impl HashU64 {
    #[cold]
    const fn hash(&self, state: SipHash24) -> SipHash24 {
        state.update_u64(self.0)
    }
}
struct HashStr<'a>(&'a str);
impl<'a> HashStr<'a> {
    #[cold]
    const fn hash(&self, state: SipHash24) -> SipHash24 {
        state.update_str(self.0)
    }
}

macro_rules! hash_field {
    (
        $(#[const_hash_with($const_hash_with:ident)])?
        $(#[slice_const_hash($slice_const_hash:expr)])?
        ($value:expr, $state:expr)
    ) => {{
        // We use _ to suppress unused variable warning.
        let value = $value;
        let state = $state;
        let _to_hash = value;
        $(let _to_hash = $const_hash_with(_to_hash);)?
        $(
            let _ = $slice_const_hash;
            let _to_hash = HashNothing(());
            let mut state = state.update_u64(value.len() as u64);
            let mut i = 0;
            while i < value.len() {
                let x = &value[i];
                state = x.hash(state);
                i += 1;
            }
        )?
        _to_hash.hash(state)
    }};
}

macro_rules! generate {
    (
        #[mod_name = $mod_name:ident]
        $(#[derive($($typeclass:ident),*)])?
        struct $name:ident $(<$a:lifetime>)? {
        $(
            $(#[const_hash_with($const_hash_with:ident)])?
            $(#[slice_const_hash($slice_const_hash:expr)])?
            $(#[serde(with = $serde_with:expr)])?
            $field:ident : $btype:ty | $otype:ty
        ),*
        $(,)?
    }) => {
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        #[repr(C)]
        pub struct $name$(<$a>)? {
            $(pub $field : $btype,)*
        }
        impl$(<$a>)? $name$(<$a>)? {
            #[cold]
            const fn hash(&self, state: SipHash24) -> SipHash24 {
                $(
                    let state = hash_field!(
                        $(#[const_hash_with($const_hash_with)])?
                        $(#[slice_const_hash($slice_const_hash)])?
                        (self.$field, state)
                    );
                )*
                state
            }
        }
    };
    (
        #[mod_name = $mod_name:ident]
        $(#[derive($($typeclass:ident),*)])?
        enum $name:ident<$a:lifetime> {
        $($varname:ident $({
            $(
                $(#[const_hash_with($const_hash_with:ident)])?
                $(#[slice_const_hash($slice_const_hash:expr)])?
                $(#[serde(with = $serde_with:expr)])?
                $field:ident : $btype:ty | $otype:ty
            ),* $(,)?
        })?),* $(,)?
    }) => {
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        #[repr(u64)]
        pub enum $name<$a> {
            $($varname $({
                $($field : $btype,)*
            })?,)*
        }
        impl<$a> $name<$a> {
            #[cold]
            const fn hash(&self, state: SipHash24) -> SipHash24 {
                match self {
                    $(
                        $name::$varname $({
                            $($field,)*
                        })? => {
                            const VAR_ID: u64 =
                                SipHash24::new(0).update_str(stringify!($varname)).finish();
                            let state = state.update_u64(VAR_ID);
                            $($(
                                let state = hash_field!(
                                    $(#[const_hash_with($const_hash_with)])?
                                    $(#[slice_const_hash($slice_const_hash)])?
                                    ($field, state)
                                );
                            )*)?
                            state
                        }
                    )*
                }
            }
        }
    };
}
include!("internal_metadata_structures.inc");

// Silence warning about unused functions. (This could alternatively be accomplished through the
// right combination of #[allow(...)] directives, but this was easier, and more precise.)
pub const _: u64 = LogRecordMetadata {
    magic_number: 0,
    hash_value: LogRecordMetadataHash { schema_hash: 0 },
    log_record_metadata_info: LogRecordMetadataInfo {
        level: Level::Info,
        message: "",
        file: "",
        module_path: "",
        cargo_pkg_version: "",
        line: 0,
        column: 0,
        fields: &[],
    },
}
.hash(SipHash24::new(0))
.finish();

impl<'a> LogRecordMetadataInfo<'a> {
    #[cold]
    pub const fn log_record_metadata_hash(&self) -> LogRecordMetadataHash {
        LogRecordMetadataHash {
            schema_hash: self.hash(SipHash24::new(SCHEMA_HASH_KEY)).finish(),
        }
    }
}
