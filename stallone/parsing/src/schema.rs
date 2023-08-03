//! See `../../common/src/internal_metadata_structures.inc` for more info on the schema and the
//! macros in this file.

use crate::{
    level_serde,
    load_from_binary::{Addr, Architecture, BinaryImageLoadable, ImageReader, LoadFromBinaryError},
};
use serde::{Deserialize, Serialize};
use stallone_common::Level;
use std::alloc::Layout;

/// Automatically generate owned data structures and code to load them from a compiled binary.
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
        }
    ) => {
        #[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize $(, $($typeclass),*)?)]
        pub struct $name {
            $($(#[serde(with = $serde_with)])? pub $field : $otype,)*
        }
        impl BinaryImageLoadable for $name {
            fn layout(arch: Architecture) -> Layout {
                let out = Layout::from_size_align(0, 1).unwrap();
                $(
                    let out = out.extend(<$otype as BinaryImageLoadable>::layout(arch)).unwrap().0;
                )*
                out.pad_to_align()
            }
            fn load(img: &mut ImageReader, ptr: Addr) -> Result<Self, LoadFromBinaryError> {
                let layout = Layout::from_size_align(0, 1).unwrap();
                $(
                    let (layout, offset) =
                        layout.extend(<$otype as BinaryImageLoadable>::layout(img.arch)).unwrap();
                    let $field: $otype = img.load(ptr + (offset as u64))?;
                )*
                let _ = layout;
                Ok($name { $($field),* })
            }
        }
        mod $mod_name {
            #[cfg(test)]
            use super::*;
            #[test]
            fn test_layout() {
                assert_eq!(
                    $name::layout(Architecture::current()),
                    Layout::new::<stallone_common::internal_metadata_structures::$name>()
                );
            }
        }
    };
    (#[mod_name = $mod_name:ident]
    $(#[derive($($typeclass:ident),*)])? enum $name:ident<$a:lifetime> {
        $($varname:ident $({
            $(
                $(#[const_hash_with($const_hash_with:ident)])?
                $(#[slice_const_hash($slice_const_hash:expr)])?
                $(#[serde(with = $serde_with:expr)])?
                $field:ident : $btype:ty | $otype:ty
            ),* $(,)?
        })?),* $(,)?
    }) => {
        #[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize $(, $($typeclass),*)?)]
        pub enum $name {
            $($varname $({
                $(
                    $(#[serde(with = $serde_with)])?
                    $field : $otype
                ),*
            })?,)*
        }

        impl BinaryImageLoadable for $name {
            fn layout(_arch: Architecture) -> Layout {
                todo!("We do not currently need the layout of enums.");
            }
            fn load(img: &mut ImageReader, mut ptr: Addr) -> Result<Self, LoadFromBinaryError> {
                // This is always a u64, regardless of the platform.
                let tag: u64 = img.load(ptr)?;
                ptr += 8;
                let mut current_disc = 0_u64;
                $(
                    if tag == current_disc {
                        $($(
                            // TODO: this assumes perfect alignment.
                            let $field: $otype = img.load(ptr)?;
                            ptr += <$otype as BinaryImageLoadable>::layout(img.arch).size() as u64;
                        )*)?
                        let _ = ptr; // Silence warning
                        return Ok($name::$varname $({
                            $($field),*
                        })?);
                    }
                    current_disc += 1;
                )*
                let _ = current_disc; // Silence warning
                // TODO: this error is highly specific to the one enum we currently care about.
                return Err(LoadFromBinaryError::UnknownValueTypeTag { tag });
            }
        }
    };
}

include!("../../common/src/internal_metadata_structures.inc");
impl ValueType {
    pub fn is_erase_from_context(&self) -> bool {
        match &self {
            ValueType::Record {
                contents: RecordType { name, fields: _ },
            } => name.as_str() == "stallone::EraseFromContext",
            _ => false,
        }
    }
}
