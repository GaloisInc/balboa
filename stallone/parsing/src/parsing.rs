use crate::{schema::*, Value};
use snafu::Snafu;

/// In serveral places in this file, we want to allocate a slice of `Value`s. In order to allocate
/// this slide, we need to initialize the elements to _something_. We use this `PLACEHOLDER_VALUE`.
const PLACEHOLDER_VALUE: Value<'static> = Value::String("If you see this string, it's a bug!");

#[derive(Debug, Snafu)]
pub enum ValueParseError {
    #[snafu(display("Unexpected EOF"))]
    UnexpectedEOF,
    #[snafu(display("Invalid UTF-8: {}", source))]
    InvalidUtf8 { source: std::str::Utf8Error },
    #[snafu(display("Illegal Enum Variant: {}. Max value is {}", variant, max))]
    IllegalEnumVariant { variant: usize, max: usize },
    #[snafu(display("Invalid char {}", value))]
    InvalidChar { value: u32 },
}

trait ReadBuffer {
    fn read_bytes(&mut self, dst: &mut [u8]) -> Result<(), ValueParseError>;
    fn read_u8(&mut self) -> Result<u8, ValueParseError> {
        let mut buf = [0; 1];
        self.read_bytes(&mut buf)?;
        Ok(buf[0])
    }
    fn read_u16(&mut self) -> Result<u16, ValueParseError> {
        let mut buf = [0; 2];
        self.read_bytes(&mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }
    fn read_u32(&mut self) -> Result<u32, ValueParseError> {
        let mut buf = [0; 4];
        self.read_bytes(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }
    fn read_u64(&mut self) -> Result<u64, ValueParseError> {
        let mut buf = [0; 8];
        self.read_bytes(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
    fn read_u128(&mut self) -> Result<u128, ValueParseError> {
        let mut buf = [0; 16];
        self.read_bytes(&mut buf)?;
        Ok(u128::from_le_bytes(buf))
    }
}
impl<'a> ReadBuffer for &'a [u8] {
    fn read_bytes(&mut self, dst: &mut [u8]) -> Result<(), ValueParseError> {
        if self.len() >= dst.len() {
            dst.copy_from_slice(&self[0..dst.len()]);
            *self = &self[dst.len()..];
            Ok(())
        } else {
            Err(ValueParseError::UnexpectedEOF)
        }
    }
}

fn parse_value<'a, 'b>(
    schema: &'b ValueType,
    body: &mut &'b [u8],
    arena: &'a bumpalo::Bump,
) -> Result<Value<'a>, ValueParseError> {
    Ok(match schema {
        ValueType::Bool => Value::Bool(body.read_u8()? != 0),
        ValueType::U8 => Value::U8(body.read_u8()?),
        ValueType::U16 => Value::U16(body.read_u16()?),
        ValueType::U32 => Value::U32(body.read_u32()?),
        ValueType::U64 => Value::U64(body.read_u64()?),
        ValueType::U128 => Value::U128(body.read_u128()?),
        ValueType::I8 => Value::I8(body.read_u8()? as i8),
        ValueType::I16 => Value::I16(body.read_u16()? as i16),
        ValueType::I32 => Value::I32(body.read_u32()? as i32),
        ValueType::I64 => Value::I64(body.read_u64()? as i64),
        ValueType::I128 => Value::I128(body.read_u128()? as i128),
        ValueType::Char => {
            let value = body.read_u32()?;
            Value::Char(std::char::from_u32(value).ok_or(ValueParseError::InvalidChar { value })?)
        }
        ValueType::String => {
            let sz = body.read_u16()? as usize;
            let bytes = arena.alloc_slice_fill_copy(sz, 0);
            body.read_bytes(bytes)?;
            Value::String(
                std::str::from_utf8(bytes)
                    .map_err(|source| ValueParseError::InvalidUtf8 { source })?,
            )
        }
        ValueType::Array {
            length: sz,
            contents,
        } if contents.as_ref() == &ValueType::U8 => {
            let sz = *sz as usize;
            let contents = arena.alloc_slice_fill_copy(sz, 0);
            body.read_bytes(contents)?;
            Value::Bytes(contents)
        }
        ValueType::Array {
            length: sz,
            contents: ty,
        } => {
            let sz = *sz as usize;
            let contents = arena.alloc_slice_fill_clone(sz, &PLACEHOLDER_VALUE);
            for dst in contents.iter_mut() {
                *dst = parse_value(ty, body, arena)?;
            }
            Value::Array(contents)
        }
        ValueType::Vector { contents } if contents.as_ref() == &ValueType::U8 => {
            let sz = body.read_u16()? as usize;
            let contents = arena.alloc_slice_fill_copy(sz, 0);
            body.read_bytes(contents)?;
            Value::Bytes(contents)
        }
        ValueType::Vector { contents: ty } => {
            let sz = body.read_u16()? as usize;
            let contents = arena.alloc_slice_fill_clone(sz, &PLACEHOLDER_VALUE);
            for dst in contents.iter_mut() {
                *dst = parse_value(ty, body, arena)?;
            }
            Value::Array(contents)
        }
        ValueType::MultiMap { key, value } => {
            let sz = body.read_u16()? as usize;
            let contents =
                arena.alloc_slice_fill_clone(sz, &(PLACEHOLDER_VALUE, PLACEHOLDER_VALUE));
            for (k, v) in contents.iter_mut() {
                *k = parse_value(key, body, arena)?;
                *v = parse_value(value, body, arena)?;
            }
            Value::MultiMap(contents)
        }
        ValueType::Record { contents: ty } => {
            let contents = arena.alloc_slice_fill_clone(ty.fields.len(), &PLACEHOLDER_VALUE);
            for (dst, field) in contents.iter_mut().zip(ty.fields.iter()) {
                *dst = parse_value(&field.ty, body, arena)?;
            }
            Value::Record(contents)
        }
        ValueType::Enum { name: _, variants } => {
            let variant_idx = body.read_u8()? as usize;
            let variant = variants
                .get(variant_idx)
                .ok_or(ValueParseError::IllegalEnumVariant {
                    variant: variant_idx,
                    max: variants.len(),
                })?;
            let contents = arena.alloc_slice_fill_clone(variant.fields.len(), &PLACEHOLDER_VALUE);
            for (dst, field) in contents.iter_mut().zip(variant.fields.iter()) {
                *dst = parse_value(&field.ty, body, arena)?;
            }
            Value::Enum {
                variant: variant_idx,
                contents,
            }
        }
    })
}

/// Parse [Value]s out of a log record.
pub fn parse_log_record_body<'a, 'b>(
    schema: &'b LogRecordMetadataInfo,
    mut body: &'b [u8],
    arena: &'a bumpalo::Bump,
) -> Result<&'a [Value<'a>], ValueParseError> {
    let contents = arena.alloc_slice_fill_clone(schema.fields.len(), &PLACEHOLDER_VALUE);
    for (dst, field) in contents.iter_mut().zip(schema.fields.iter()) {
        *dst = parse_value(&field.type_id, &mut body, arena)?;
    }
    Ok(contents)
}
