#![allow(unused_variables, unused_mut)]

use uuid::Uuid;

use crate::{
    internal_metadata_structures::{EnumDiscriminant, RecordType, RecordTypeField, ValueType},
    IsPod, LoggableMetadata,
};
use std::path::PathBuf;
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    ops::Deref,
    path::Path,
    rc::Rc,
    str::Utf8Error,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use std::{num::ParseIntError, os::unix::ffi::OsStrExt};

const MAX_COUNT: usize = u16::MAX as usize;

macro_rules! serialize_primitive {
    ($t:ty, $lrt:expr) => {
        impl LoggableMetadata for $t {
            const TYPE_ID: $crate::ValueType<'static> = $lrt;
            const IS_POD: Option<IsPod<Self>> = Some(unsafe { IsPod::new() });

            #[inline(always)]
            fn log_size(&self) -> usize {
                std::mem::size_of::<$t>()
            }

            #[inline(always)]
            fn log_serialize(&self, buf: &mut [u8]) {
                buf.copy_from_slice(&self.to_le_bytes());
            }
        }
    };
}

impl LoggableMetadata for bool {
    // This is _explicitly not_ POD.
    const TYPE_ID: ValueType<'static> = ValueType::Bool;

    #[inline(always)]
    fn log_size(&self) -> usize {
        1
    }

    #[inline(always)]
    fn log_serialize(&self, buf: &mut [u8]) {
        buf[0] = *self as u8;
    }
}

serialize_primitive!(u8, ValueType::U8);
serialize_primitive!(u16, ValueType::U16);
serialize_primitive!(u32, ValueType::U32);
serialize_primitive!(u64, ValueType::U64);
serialize_primitive!(u128, ValueType::U128);
serialize_primitive!(i8, ValueType::I8);
serialize_primitive!(i16, ValueType::I16);
serialize_primitive!(i32, ValueType::I32);
serialize_primitive!(i64, ValueType::I64);
serialize_primitive!(i128, ValueType::I128);

// For portability, we encode usize and isize as 64-bit
impl LoggableMetadata for usize {
    const TYPE_ID: ValueType<'static> = u64::TYPE_ID;
    const IS_POD: Option<IsPod<Self>> =
        if std::mem::size_of::<u64>() == std::mem::size_of::<usize>() {
            Some(unsafe { IsPod::new() })
        } else {
            None
        };

    #[inline(always)]
    fn log_size(&self) -> usize {
        (*self as u64).log_size()
    }

    #[inline(always)]
    fn log_serialize(&self, buf: &mut [u8]) {
        (*self as u64).log_serialize(buf)
    }
}

impl LoggableMetadata for isize {
    const TYPE_ID: ValueType<'static> = i64::TYPE_ID;
    const IS_POD: Option<IsPod<Self>> =
        if std::mem::size_of::<i64>() == std::mem::size_of::<isize>() {
            Some(unsafe { IsPod::new() })
        } else {
            None
        };

    #[inline(always)]
    fn log_size(&self) -> usize {
        (*self as i64).log_size()
    }

    #[inline(always)]
    fn log_serialize(&self, buf: &mut [u8]) {
        (*self as i64).log_serialize(buf)
    }
}

impl LoggableMetadata for char {
    const TYPE_ID: ValueType<'static> = ValueType::Char;

    #[inline(always)]
    fn log_size(&self) -> usize {
        4
    }

    #[inline(always)]
    fn log_serialize(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&(*self as u32).to_le_bytes()[..]);
    }
}

impl<'a> LoggableMetadata for &'a str {
    const TYPE_ID: ValueType<'static> = ValueType::String;

    #[inline(always)]
    fn log_size(&self) -> usize {
        len_slice(self.as_bytes())
    }

    #[inline(always)]
    fn log_serialize(&self, buf: &mut [u8]) {
        write_slice(self.as_bytes(), buf)
    }
}

impl LoggableMetadata for String {
    const TYPE_ID: ValueType<'static> = ValueType::String;

    #[inline(always)]
    fn log_size(&self) -> usize {
        self.as_str().log_size()
    }

    #[inline(always)]
    fn log_serialize(&self, buf: &mut [u8]) {
        self.as_str().log_serialize(buf);
    }
}

macro_rules! serialize_owned {
    ($name:ident) => {
        impl<T: LoggableMetadata> LoggableMetadata for $name<T> {
            const TYPE_ID: ValueType<'static> = T::TYPE_ID;

            #[inline(always)]
            fn log_size(&self) -> usize {
                let value: &T = self.deref();
                value.log_size()
            }

            #[inline(always)]
            fn log_serialize(&self, buf: &mut [u8]) {
                let value: &T = self.deref();
                value.log_serialize(buf)
            }
        }
    };
}

serialize_owned!(Box);
serialize_owned!(Arc);
serialize_owned!(Rc);

macro_rules! serialize_struct {
    ($name:ident ($this:ident) {
        $($field:ident : $ty:ty = $getter:expr),*
    }) => {
        impl LoggableMetadata for $name {
            const TYPE_ID: ValueType<'static> = ValueType::Record {
                contents: RecordType {
                    name: concat!("std::", stringify!($name)),
                    fields: &[
                        $(
                            RecordTypeField {
                                name: stringify!($field),
                                ty: &<$ty as LoggableMetadata>::TYPE_ID,
                            }
                        ),*
                    ],
                },
            };

            #[inline(always)]
            fn log_size(&self) -> usize {
                let $this = self;
                let _ = $this;
                let mut out = 0;
                $(
                    out += $getter.log_size();
                )*
                out
            }
            #[inline(always)]
            fn log_serialize(&self, mut buf: &mut [u8]) {
                let $this = self;
                let _ = $this;
                $(
                    let x = $getter;
                    let sz = x.log_size();
                    x.log_serialize(&mut buf[0..sz]);
                    buf = &mut buf[sz..];
                )*
                let _ = buf;
            }
        }
    };
}

macro_rules! serialize_enum {
    (<$($targ:ident),*>, $name:ident {
        $(
            $variant:ident $(($($value:ident : $ty:ident),*))?
        ),*
    }) => {
        impl<$($targ: LoggableMetadata),*> LoggableMetadata for $name<$($targ),*> {
            const TYPE_ID: ValueType<'static> = ValueType::Enum {
                name: concat!("std::", stringify!($name)),
                variants: &[
                    $(RecordType {
                        name: stringify!($variant),
                        fields: &[
                            $($(
                                RecordTypeField {
                                    name: stringify!($value),
                                    ty: &<$ty as LoggableMetadata>::TYPE_ID,
                                }
                            ),*)?
                        ],
                    }),*
                ],
            };
            #[inline(always)]
            fn log_size(&self) -> usize {
                let mut out = 1;
                match self {
                    $(
                        $variant$(($($value),*))? => {
                            $($(out += <$ty as LoggableMetadata>::log_size($value);)*)?
                        }
                    ),*
                }
                out
            }
            #[inline(always)]
            fn log_serialize(&self, mut buf: &mut [u8]) {
                let mut disc: EnumDiscriminant = 0;
                $(
                    if let $variant$(($($value),*))? = self {
                        buf[0] = disc;
                        buf = &mut buf[1..];
                        $($(
                            let sz = <$ty as LoggableMetadata>::log_size($value);
                            <$ty as LoggableMetadata>::log_serialize($value, &mut buf[0..sz]);
                            buf = &mut buf[sz..];
                        )*)?
                    }
                    disc += 1;
                )*
                let _ = disc;
                let _ = buf;
            }
        }
    };
}

serialize_enum!(<T>, Option {
    None,
    Some(value: T)
});

serialize_enum!(<O, E>, Result {
    Ok(value: O),
    Err(value: E)
});

impl<T: LoggableMetadata> LoggableMetadata for Vec<T> {
    const TYPE_ID: ValueType<'static> = ValueType::Vector {
        contents: &T::TYPE_ID,
    };

    #[inline(always)]
    fn log_size(&self) -> usize {
        self.as_slice().log_size()
    }

    #[inline(always)]
    fn log_serialize(&self, buf: &mut [u8]) {
        self.as_slice().log_serialize(buf)
    }
}

#[inline(always)]
fn write_slice<'a, T: LoggableMetadata>(slice: &'a [T], mut dst: &mut [u8]) {
    let len = slice.len().min(MAX_COUNT as usize);
    dst[0..2].copy_from_slice(&(len as u16).to_le_bytes());
    dst = &mut dst[2..];
    write_slice_body(slice, dst);
}

#[inline(always)]
fn write_slice_body<'a, T: LoggableMetadata>(slice: &'a [T], dst: &mut [u8]) {
    if cfg!(target_endian = "little") && T::IS_POD.is_some() {
        let len = slice.len().min(MAX_COUNT);
        let size = len * std::mem::size_of::<T>();
        assert!(dst.len() >= size);
        unsafe {
            std::ptr::copy_nonoverlapping(slice.as_ptr() as *const u8, dst.as_mut_ptr(), size);
        }
    } else {
        write_iter_body(slice.iter(), dst);
    }
}

#[inline(always)]
fn write_iter_body<'a, T: LoggableMetadata>(
    iter: impl Iterator<Item = T> + 'a,
    mut dst: &mut [u8],
) {
    for x in iter.take(MAX_COUNT) {
        let s = x.log_size();
        x.log_serialize(&mut dst[0..s]);
        dst = &mut dst[s..];
    }
}

#[inline(always)]
fn write_iter<'a, T: LoggableMetadata>(
    iter: impl ExactSizeIterator<Item = T> + 'a,
    mut dst: &mut [u8],
) {
    let len = iter.len().min(MAX_COUNT);
    dst[0..2].copy_from_slice(&(len as u16).to_le_bytes());
    dst = &mut dst[2..];
    write_iter_body(iter, dst);
}

#[inline(always)]
fn len_iter<'a, T: LoggableMetadata>(iter: impl ExactSizeIterator<Item = T> + 'a) -> usize {
    let len = iter.len().min(MAX_COUNT);
    2 + iter
        .take(len)
        .map::<usize, _>(|item| item.log_size())
        .sum::<usize>()
}

#[inline(always)]
fn len_slice<'a, T: LoggableMetadata>(slice: &'a [T]) -> usize {
    if cfg!(target_endian = "little") && T::IS_POD.is_some() {
        let len = slice.len().min(MAX_COUNT);
        2 + len * std::mem::size_of::<T>()
    } else {
        len_iter(slice.iter())
    }
}

impl<T: LoggableMetadata> LoggableMetadata for [T] {
    const TYPE_ID: ValueType<'static> = ValueType::Vector {
        contents: &T::TYPE_ID,
    };

    #[inline(always)]
    fn log_size(&self) -> usize {
        len_slice(self)
    }

    #[inline(always)]
    fn log_serialize(&self, buf: &mut [u8]) {
        write_slice(self, buf)
    }
}

impl<const N: usize> LoggableMetadata for arrayvec::ArrayString<N> {
    const TYPE_ID: ValueType<'static> = ValueType::String;

    #[inline(always)]
    fn log_size(&self) -> usize {
        self.as_str().log_size()
    }

    #[inline(always)]
    fn log_serialize(&self, buf: &mut [u8]) {
        self.as_str().log_serialize(buf);
    }
}

impl<T: LoggableMetadata, const N: usize> LoggableMetadata for arrayvec::ArrayVec<T, N> {
    const TYPE_ID: ValueType<'static> = ValueType::Vector {
        contents: &T::TYPE_ID,
    };

    #[inline(always)]
    fn log_size(&self) -> usize {
        len_slice(self.as_slice())
    }

    #[inline(always)]
    fn log_serialize(&self, buf: &mut [u8]) {
        write_slice(self.as_slice(), buf)
    }
}

impl<A: smallvec::Array<Item = T>, T: LoggableMetadata> LoggableMetadata for smallvec::SmallVec<A> {
    const TYPE_ID: ValueType<'static> = ValueType::Vector {
        contents: &T::TYPE_ID,
    };

    #[inline(always)]
    fn log_size(&self) -> usize {
        len_slice(self.as_slice())
    }

    #[inline(always)]
    fn log_serialize(&self, buf: &mut [u8]) {
        write_slice(self.as_slice(), buf)
    }
}

impl<'a, T: ?Sized + LoggableMetadata + 'a> LoggableMetadata for &'a T {
    const TYPE_ID: ValueType<'static> = T::TYPE_ID;

    #[inline(always)]
    fn log_size(&self) -> usize {
        (**self).log_size()
    }

    #[inline(always)]
    fn log_serialize(&self, buf: &mut [u8]) {
        (**self).log_serialize(buf)
    }
}

impl<'a, T: ?Sized + LoggableMetadata + 'a> LoggableMetadata for &'a mut T {
    const TYPE_ID: ValueType<'static> = T::TYPE_ID;

    #[inline(always)]
    fn log_size(&self) -> usize {
        (**self).log_size()
    }

    #[inline(always)]
    fn log_serialize(&self, buf: &mut [u8]) {
        (**self).log_serialize(buf)
    }
}

impl<T: ?Sized> LoggableMetadata for std::marker::PhantomData<T> {
    const TYPE_ID: ValueType<'static> = <() as LoggableMetadata>::TYPE_ID;

    #[inline(always)]
    fn log_size(&self) -> usize {
        0
    }

    #[inline(always)]
    fn log_serialize(&self, _buf: &mut [u8]) {}
}

macro_rules! serialize_iter {
    ($T:ident, $ty:ty) => {
        impl<$T: LoggableMetadata> LoggableMetadata for $ty {
            const TYPE_ID: ValueType<'static> = ValueType::Vector {
                contents: &$T::TYPE_ID,
            };

            #[inline(always)]
            fn log_size(&self) -> usize {
                len_iter(self.iter())
            }

            #[inline(always)]
            fn log_serialize(&self, buf: &mut [u8]) {
                write_iter(self.iter(), buf)
            }
        }
    };
}
serialize_iter!(T, std::collections::BTreeSet<T>);
serialize_iter!(T, std::collections::BinaryHeap<T>);
serialize_iter!(T, std::collections::LinkedList<T>);
serialize_iter!(T, std::collections::VecDeque<T>);
impl<T: LoggableMetadata, S> LoggableMetadata for HashSet<T, S> {
    const TYPE_ID: ValueType<'static> = ValueType::Vector {
        contents: &T::TYPE_ID,
    };

    #[inline(always)]
    fn log_size(&self) -> usize {
        len_iter(self.iter())
    }

    #[inline(always)]
    fn log_serialize(&self, buf: &mut [u8]) {
        write_iter(self.iter(), buf)
    }
}

impl<T: LoggableMetadata, const N: usize> LoggableMetadata for [T; N] {
    const TYPE_ID: ValueType<'static> = ValueType::Array {
        length: N as u64,
        contents: &T::TYPE_ID,
    };
    const IS_POD: Option<IsPod<Self>> = if let Some(_) = T::IS_POD {
        Some(unsafe { IsPod::new() })
    } else {
        None
    };

    #[inline(always)]
    fn log_size(&self) -> usize {
        self.iter().map(|x| x.log_size()).sum()
    }

    #[inline(always)]
    fn log_serialize(&self, buf: &mut [u8]) {
        write_slice_body(&self[..], buf);
    }
}

// Map values are serialized as if they are an array of tuples.
impl<K: LoggableMetadata, V: LoggableMetadata, S> LoggableMetadata
    for std::collections::HashMap<K, V, S>
{
    const TYPE_ID: ValueType<'static> = ValueType::MultiMap {
        key: &K::TYPE_ID,
        value: &V::TYPE_ID,
    };

    #[inline(always)]
    fn log_size(&self) -> usize {
        len_iter(self.iter())
    }

    #[inline(always)]
    fn log_serialize(&self, buf: &mut [u8]) {
        write_iter(self.iter(), buf)
    }
}

impl<K: LoggableMetadata, V: LoggableMetadata> LoggableMetadata
    for std::collections::BTreeMap<K, V>
{
    const TYPE_ID: ValueType<'static> = ValueType::MultiMap {
        key: &K::TYPE_ID,
        value: &V::TYPE_ID,
    };

    #[inline(always)]
    fn log_size(&self) -> usize {
        len_iter(self.iter())
    }

    #[inline(always)]
    fn log_serialize(&self, buf: &mut [u8]) {
        write_iter(self.iter(), buf)
    }
}

serialize_struct!(Ipv4Addr (this) {
    value: [u8; 4] = this.octets()
});

serialize_struct!(Ipv6Addr (this) {
    octets: [u8; 16] = this.octets()
});

serialize_struct!(Uuid (this) {
    bytes: [u8; 16] = *this.as_bytes()
});

mod ip_addr {
    use super::*;
    use IpAddr::{V4, V6};
    serialize_enum!(<>, IpAddr {
        V4(value: Ipv4Addr),
        V6(value: Ipv6Addr)
    });
}

serialize_struct!(SocketAddrV4(this) {
    ip: Ipv4Addr = this.ip(),
    port: u16 = this.port()
});

serialize_struct!(SocketAddrV6(this) {
    ip: Ipv6Addr = this.ip(),
    port: u16 = this.port()
});

mod socket_addr {
    use super::*;
    use SocketAddr::{V4, V6};
    serialize_enum!(<>, SocketAddr {
        V4(value: SocketAddrV4),
        V6(value: SocketAddrV6)
    });
}

serialize_struct!(Path(this) {
    bytes: [u8] = this.as_os_str().as_bytes()
});

impl LoggableMetadata for PathBuf {
    const TYPE_ID: ValueType<'static> = Path::TYPE_ID;

    #[inline(always)]
    fn log_size(&self) -> usize {
        self.as_path().log_size()
    }

    #[inline(always)]
    fn log_serialize(&self, buf: &mut [u8]) {
        self.as_path().log_serialize(buf)
    }
}

serialize_struct!(Duration(this) {
    seconds: u64 = this.as_secs(),
    subsec_nanos: u32 = this.subsec_nanos()
});

serialize_struct!(SystemTime(this) {
    duration_since_epoch: Duration = this
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime must be later than UNIX_EPOCH")
});

serialize_struct!(Utf8Error(this) {
    valid_up_to: usize = this.valid_up_to(),
    error_len: Option<usize> = this.error_len()
});

serialize_struct!(ParseIntError(this) {
    // TODO: once the kind() method gets stabilized, add that here.
});

macro_rules! tuple_serialize {
    ($([$n:tt] $id:ident),*) => {
        impl<$($id: LoggableMetadata),*> LoggableMetadata for ($($id,)*) {
            const TYPE_ID: ValueType<'static> = ValueType::Record {
                contents: RecordType {
                    name: "Tuple",
                    fields: &[
                        $(
                            RecordTypeField {
                                name: stringify!($n),
                                ty: &<$id as LoggableMetadata>::TYPE_ID,
                            }
                        ),*
                    ],
                },
            };

            #[inline(always)]
            fn log_size(&self) -> usize {
                let mut out = 0;
                $(out += (self.$n).log_size();)*
                out
            }

            #[inline(always)]
            fn log_serialize(&self, mut buf: &mut [u8]) {
                $(
                    let sz = (self.$n).log_size();
                    (self.$n).log_serialize(&mut buf[0..sz]);
                    buf = &mut buf[sz..];
                    let _ = (&buf, sz); // silence warning
                )*
            }
        }
    };
}

tuple_serialize!();
tuple_serialize!([0] T0);
tuple_serialize!([0] T0, [1] T1);
tuple_serialize!([0] T0, [1] T1, [2] T2);
tuple_serialize!([0] T0, [1] T1, [2] T2, [3] T3);
tuple_serialize!([0] T0, [1] T1, [2] T2, [3] T3, [4] T4);
tuple_serialize!([0] T0, [1] T1, [2] T2, [3] T3, [4] T4, [5] T5);
tuple_serialize!([0] T0, [1] T1, [2] T2, [3] T3, [4] T4, [5] T5, [6] T6);
tuple_serialize!([0] T0, [1] T1, [2] T2, [3] T3, [4] T4, [5] T5, [6] T6, [7] T7);
tuple_serialize!([0] T0, [1] T1, [2] T2, [3] T3, [4] T4, [5] T5, [6] T6, [7] T7, [8] T8);
tuple_serialize!([0] T0, [1] T1, [2] T2, [3] T3, [4] T4, [5] T5, [6] T6, [7] T7, [8] T8, [9] T9);
tuple_serialize!([0] T0, [1] T1, [2] T2, [3] T3, [4] T4, [5] T5, [6] T6, [7] T7, [8] T8, [9] T9, [10] T10);
tuple_serialize!([0] T0, [1] T1, [2] T2, [3] T3, [4] T4, [5] T5, [6] T6, [7] T7, [8] T8, [9] T9, [10] T10, [11] T11);
