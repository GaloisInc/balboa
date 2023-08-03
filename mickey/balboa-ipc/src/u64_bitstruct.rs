//! Make structs with bitfields that can be encoded as u64.

// TODO: unify this with wrapper structs and stuff.

macro_rules! bit_struct_u64 {
    ($(
        // TODO: support pub
        #[quickcheck_test($test_name:ident)]
        struct $name:ident {
            $(
            $field:ident : $nbits:expr $(,)?
            ),*
        }
    )*) => {$(
        #[derive(Clone, Copy, PartialEq, Eq, Debug, stallone::LoggableMetadata)]
        pub struct $name {
            $(
            $field : u64,
            )*
        }
        impl std::convert::TryFrom<$name> for u64 {
            // TODO: better error handling.
            type Error = ();
            fn try_from(x: $name) -> Result<Self, Self::Error> {
                $(
                    if x.$field > ((1 << $nbits) - 1) {
                        return Err(());
                    }
                )*
                let mut bit_idx = 0;
                let mut out = 0;
                $(
                    out |= x.$field << bit_idx;
                    bit_idx += $nbits;
                )*
                let _ = bit_idx;
                Ok(out)
            }
        }
        impl From<u64> for $name {
            fn from(mut x: u64) -> Self {
                $(
                    let $field = x & ((1 << $nbits) - 1);
                    x >>= $nbits;
                )*
                let _ = x;
                $name {
                    $($field),*
                }
            }
        }
        static_assertions::const_assert_eq!(64, 0 $(+ $nbits)*);
        #[cfg(test)]
        impl proptest::prelude::Arbitrary for $name {
            type Parameters = ();
            type Strategy = proptest::prelude::BoxedStrategy<Self>;
            fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
                use proptest::strategy::Strategy;
                [$(
                    0_u64..(1 << $nbits),
                )*].prop_map(|arr| {
                    let mut i = 0;
                    $(
                        let $field = arr[i];
                        i += 1;
                    )*
                    let _ = i;
                    $name { $($field),* }
                }).boxed()
            }
        }
        #[cfg(test)]
        proptest::proptest! {
            #[test]
            fn $test_name(x in proptest::prelude::any::<$name>()) {
                proptest::prop_assert_eq!(
                    $name::from(<u64 as std::convert::TryFrom<$name>>::try_from(x).unwrap()),
                    x
                );
            }
        }
    )*};
}
