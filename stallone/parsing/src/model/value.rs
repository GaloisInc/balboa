use crate::schema::ValueType;
use parking_lot::RwLock;
use serde::ser::{
    SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
    SerializeTupleStruct, SerializeTupleVariant,
};
use serde::{Deserialize, Serialize, Serializer};
use std::collections::HashMap;
use std::fmt::Debug;

/// A logged value, which is heap-allocated.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum OwnedValue {
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    Char(char),
    String(String),
    #[serde(with = "serde_bytes")]
    Bytes(Vec<u8>),
    Array(Vec<OwnedValue>),
    MultiMap(Vec<(OwnedValue, OwnedValue)>),
    Record(Vec<OwnedValue>),
    Enum {
        variant: usize,
        contents: Vec<OwnedValue>,
    },
}

/// A type which can be converted to a [GenericValue]. See that type for more info.
pub trait AsGenericValue: Debug + Sized {
    fn as_generic_value<'a>(&'a self) -> GenericValue<'a, Self>;
}

impl AsGenericValue for OwnedValue {
    fn as_generic_value<'a>(&'a self) -> GenericValue<'a, Self> {
        use GenericValue as G;
        use OwnedValue as V;
        match self {
            V::Bool(x) => G::Bool(*x),
            V::U8(x) => G::U8(*x),
            V::U16(x) => G::U16(*x),
            V::U32(x) => G::U32(*x),
            V::U64(x) => G::U64(*x),
            V::U128(x) => G::U128(*x),
            V::I8(x) => G::I8(*x),
            V::I16(x) => G::I16(*x),
            V::I32(x) => G::I32(*x),
            V::I64(x) => G::I64(*x),
            V::I128(x) => G::I128(*x),
            V::Char(x) => G::Char(*x),
            V::String(x) => G::String(&x),
            V::Bytes(x) => G::Bytes(&x),
            V::Array(x) => G::Array(x.as_slice()),
            V::MultiMap(x) => G::MultiMap(x.as_slice()),
            V::Record(x) => G::Record(x.as_slice()),
            V::Enum { variant, contents } => G::Enum {
                variant: *variant,
                contents: contents.as_slice(),
            },
        }
    }
}

/// A borrowed value (that has been logged).
#[derive(Clone, Copy, Debug, Serialize)]
pub enum Value<'a> {
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    Char(char),
    String(&'a str),
    #[serde(with = "serde_bytes")]
    Bytes(&'a [u8]),
    Array(&'a [Value<'a>]),
    MultiMap(&'a [(Value<'a>, Value<'a>)]),
    Record(&'a [Value<'a>]),
    Enum {
        variant: usize,
        contents: &'a [Value<'a>],
    },
}

impl<'a> AsGenericValue for Value<'a> {
    fn as_generic_value<'b>(&'b self) -> GenericValue<'b, Self> {
        use GenericValue as G;
        use Value as V;
        match self {
            V::Bool(x) => G::Bool(*x),
            V::U8(x) => G::U8(*x),
            V::U16(x) => G::U16(*x),
            V::U32(x) => G::U32(*x),
            V::U64(x) => G::U64(*x),
            V::U128(x) => G::U128(*x),
            V::I8(x) => G::I8(*x),
            V::I16(x) => G::I16(*x),
            V::I32(x) => G::I32(*x),
            V::I64(x) => G::I64(*x),
            V::I128(x) => G::I128(*x),
            V::Char(x) => G::Char(*x),
            V::String(x) => G::String(&x),
            V::Bytes(x) => G::Bytes(&x),
            V::Array(x) => G::Array(x),
            V::MultiMap(x) => G::MultiMap(x),
            V::Record(x) => G::Record(x),
            V::Enum { variant, contents } => G::Enum {
                variant: *variant,
                contents,
            },
        }
    }
}
/// A reference to either [Value] or [OwnedValue].
///
/// # Rationale
/// We want some pieces of code to be able to take either an [OwnedValue] or a [Value].
/// `Value != &OwnedValue`, so we create a new data structure which we can create from either value
/// type.
///
/// There are a number of preferable alternatives to having 3 value types. One, for example,
/// would be to have an openly recursive `GenericValue`, however the rust cycle checker doesn't
/// allow for openly recursive types.
#[derive(Debug)]
pub enum GenericValue<'a, T: AsGenericValue> {
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    Char(char),
    String(&'a str),
    Bytes(&'a [u8]),
    Array(&'a [T]),
    MultiMap(&'a [(T, T)]),
    Record(&'a [T]),
    Enum { variant: usize, contents: &'a [T] },
}

impl<'a> Value<'a> {
    pub fn copy_to_arena<'b>(&self, arena: &'b bumpalo::Bump) -> Value<'b> {
        use Value::*;
        match self {
            Bool(x) => Bool(*x),
            U8(x) => U8(*x),
            U16(x) => U16(*x),
            U32(x) => U32(*x),
            U64(x) => U64(*x),
            U128(x) => U128(*x),
            I8(x) => I8(*x),
            I16(x) => I16(*x),
            I32(x) => I32(*x),
            I64(x) => I64(*x),
            I128(x) => I128(*x),
            Char(x) => Char(*x),
            String(x) => String(arena.alloc_str(*x)),
            Bytes(x) => Bytes(arena.alloc_slice_copy(*x)),
            Array(x) => {
                Array(arena.alloc_slice_fill_iter(x.iter().map(|v| v.copy_to_arena(arena))))
            }
            MultiMap(x) => MultiMap(
                arena.alloc_slice_fill_iter(
                    x.iter()
                        .map(|(k, v)| (k.copy_to_arena(arena), v.copy_to_arena(arena))),
                ),
            ),
            Record(x) => {
                Record(arena.alloc_slice_fill_iter(x.iter().map(|v| v.copy_to_arena(arena))))
            }
            Enum { variant, contents } => Enum {
                variant: *variant,
                contents: arena
                    .alloc_slice_fill_iter(contents.iter().map(|v| v.copy_to_arena(arena))),
            },
        }
    }

    pub fn to_owned(&self) -> OwnedValue {
        match self {
            Value::Bool(x) => OwnedValue::Bool(*x),
            Value::U8(x) => OwnedValue::U8(*x),
            Value::U16(x) => OwnedValue::U16(*x),
            Value::U32(x) => OwnedValue::U32(*x),
            Value::U64(x) => OwnedValue::U64(*x),
            Value::U128(x) => OwnedValue::U128(*x),
            Value::I8(x) => OwnedValue::I8(*x),
            Value::I16(x) => OwnedValue::I16(*x),
            Value::I32(x) => OwnedValue::I32(*x),
            Value::I64(x) => OwnedValue::I64(*x),
            Value::I128(x) => OwnedValue::I128(*x),
            Value::Char(x) => OwnedValue::Char(*x),
            Value::String(x) => OwnedValue::String(x.to_string()),
            Value::Bytes(x) => OwnedValue::Bytes(x.to_vec()),
            Value::Array(x) => OwnedValue::Array(x.iter().map(|y| y.to_owned()).collect()),
            Value::MultiMap(x) => OwnedValue::MultiMap(
                x.iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect(),
            ),
            Value::Record(x) => OwnedValue::Record(x.iter().map(|y| y.to_owned()).collect()),
            Value::Enum { variant, contents } => OwnedValue::Enum {
                variant: *variant,
                contents: contents.iter().map(|y| y.to_owned()).collect(),
            },
        }
    }
}

lazy_static::lazy_static! {
    // Due to https://github.com/serde-rs/serde/issues/708, we have to jump through hoops.
    // TODO: there's got to be a better way!
    static ref STATIC_STRING_CACHE: RwLock<HashMap<String, &'static str>> =
        RwLock::new(HashMap::new());
}

/// Turn a `str` into `&'static str`, caching the output.
///
/// Be careful to avoid calling this function with too many distinct strings, since the result
/// can never be freed.
fn static_string(x: &str) -> &'static str {
    if let Some(out) = STATIC_STRING_CACHE.read().get(x) {
        return *out;
    }
    *STATIC_STRING_CACHE
        .write()
        .entry(x.to_string())
        .or_insert_with(|| Box::leak(x.to_string().into_boxed_str()))
}

/// [Value]s do not have an inherently associated [ValueType]. As a result, [Serialize]-ing a
/// [Value] (or an [OwnedValue]) with serde will, for example, not contain the names of fields
/// in serialized structs. To serialize a value with its associated type, you can serialize
/// `SerializeValueWithType(my_value, my_value_type)`.
///
/// # Panics
/// Serializing a value with an incorrect type will panic.
pub struct SerializeValueWithType<'a, T: AsGenericValue>(pub &'a T, pub &'a ValueType);
impl<'a, T: AsGenericValue> Serialize for SerializeValueWithType<'a, T> {
    fn serialize<S>(&self, s: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        use GenericValue as V;
        use ValueType as T;
        match (self.0.as_generic_value(), self.1) {
            (V::Bool(x), T::Bool) => s.serialize_bool(x),
            (V::U8(x), T::U8) => s.serialize_u8(x),
            (V::U16(x), T::U16) => s.serialize_u16(x),
            (V::U32(x), T::U32) => s.serialize_u32(x),
            (V::U64(x), T::U64) => s.serialize_u64(x),
            (V::U128(x), T::U128) => s.serialize_u128(x),
            (V::I8(x), T::I8) => s.serialize_i8(x),
            (V::I16(x), T::I16) => s.serialize_i16(x),
            (V::I32(x), T::I32) => s.serialize_i32(x),
            (V::I64(x), T::I64) => s.serialize_i64(x),
            (V::I128(x), T::I128) => s.serialize_i128(x),
            (V::Char(x), T::Char) => s.serialize_char(x),
            (V::String(x), T::String) => s.serialize_str(x),
            (V::Array(x), T::Array { length, contents }) => {
                assert_eq!(x.len(), *length as usize);
                let mut s = s.serialize_seq(Some(x.len()))?;
                for y in x {
                    s.serialize_element(&SerializeValueWithType(y, contents))?;
                }
                s.end()
            }
            (V::Array(x), T::Vector { contents }) => {
                let mut s = s.serialize_seq(Some(x.len()))?;
                for y in x {
                    s.serialize_element(&SerializeValueWithType(y, &contents))?;
                }
                s.end()
            }
            (V::Bytes(x), T::Array { length, contents }) => {
                assert_eq!(x.len(), *length as usize);
                assert_eq!(contents.as_ref(), &ValueType::U8);
                s.serialize_bytes(x)
            }
            (V::Bytes(x), T::Vector { contents }) => {
                assert_eq!(contents.as_ref(), &ValueType::U8);
                s.serialize_bytes(x)
            }
            (V::MultiMap(x), T::MultiMap { key, value }) => {
                let mut s = s.serialize_map(Some(x.len()))?;
                for (k, v) in x {
                    s.serialize_entry(
                        &SerializeValueWithType(k, &key),
                        &SerializeValueWithType(v, &value),
                    )?;
                }
                s.end()
            }
            (V::Record(x), T::Record { contents }) => {
                assert_eq!(x.len(), contents.fields.len());
                if x.is_empty() {
                    if contents.name.as_str() == "Tuple" {
                        s.serialize_unit()
                    } else {
                        s.serialize_unit_struct(static_string(&contents.name))
                    }
                } else if contents.fields[0].name.as_str() == "0" {
                    // Tuple structs use numbers as their field names. Since we can't name a
                    // non-tuple struct field as "0" in valid Rust, this lets us determine whether
                    // we should be treating a type as a tuple or not.
                    if contents.name.as_str() == "Tuple" {
                        let mut s = s.serialize_tuple(x.len())?;
                        for (y, field) in x.iter().zip(contents.fields.iter()) {
                            s.serialize_element(&SerializeValueWithType(y, &field.ty))?;
                        }
                        s.end()
                    } else {
                        let mut s =
                            s.serialize_tuple_struct(static_string(&contents.name), x.len())?;
                        for (y, field) in x.iter().zip(contents.fields.iter()) {
                            s.serialize_field(&SerializeValueWithType(y, &field.ty))?;
                        }
                        s.end()
                    }
                } else {
                    // This struct has non-numeric names.
                    let mut s = s.serialize_struct(static_string(&contents.name), x.len())?;
                    for (y, field) in x.iter().zip(contents.fields.iter()) {
                        s.serialize_field(
                            static_string(&field.name),
                            &SerializeValueWithType(y, &field.ty),
                        )?;
                    }
                    s.end()
                }
            }
            (V::Enum { variant, contents }, T::Enum { name, variants }) => {
                assert!(variant < variants.len());
                let variant_idx = variant as u32;
                let variant = &variants[variant];
                assert_eq!(contents.len(), variant.fields.len());
                if contents.is_empty() {
                    s.serialize_unit_variant(
                        static_string(&name),
                        variant_idx,
                        static_string(&variant.name),
                    )
                } else if variant.fields[0].name.as_str() == "0" {
                    let mut s = s.serialize_tuple_variant(
                        static_string(&name),
                        variant_idx,
                        static_string(&variant.name),
                        contents.len(),
                    )?;
                    for (y, field) in contents.iter().zip(variant.fields.iter()) {
                        s.serialize_field(&SerializeValueWithType(y, &field.ty))?;
                    }
                    s.end()
                } else {
                    let mut s = s.serialize_struct_variant(
                        static_string(&name),
                        variant_idx,
                        static_string(&variant.name),
                        contents.len(),
                    )?;
                    for (y, field) in contents.iter().zip(variant.fields.iter()) {
                        s.serialize_field(
                            static_string(&field.name),
                            &SerializeValueWithType(y, &field.ty),
                        )?;
                    }
                    s.end()
                }
            }
            // TODO: special-case some well-known types, so they serialize in a prettier format.
            (v, t) => panic!("Value {:?} doesn't match type {:?}", v, t),
        }
    }
}
