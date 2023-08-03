//! Decompress, parse, and consume stallone logs.

mod contextualize;
mod load_from_binary;
mod model;
mod parsing;
mod schema;

mod level_serde {
    use serde::{
        de::{Error, Unexpected},
        Deserialize, Deserializer, Serializer,
    };
    use stallone_common::Level;

    pub(crate) fn serialize<S>(level: &Level, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_u8(*level as u8)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Level, D::Error>
    where
        D: Deserializer<'de>,
    {
        let byte = u8::deserialize(deserializer)?;
        Level::try_from(byte).map_err(|_| {
            D::Error::invalid_value(Unexpected::Unsigned(byte.into()), &"a level byte")
        })
    }
}

pub use contextualize::*;
pub use load_from_binary::*;
pub use model::*;
pub use parsing::*;
pub use schema::*;
