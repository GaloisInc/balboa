// This is a bit of a dirty trick. It's the sort of thing that you'd find in C code, and typically
// not in Rust. Here's why were doing it:
// We need to generate two sets of data structures: one "Owned" set (which we can
// `#[derive(Deserialize)]` for), and one "Borrowed" set, where references and slices are used
// exclusively, instead of owned data structures. The Borrowed set will be generated at compile-time
// by the stallone log library, while the Owned set will be the set that's parsed into. Rather than
// manually writing both sets and making sure that they're in sync, we instead have this file
// which will be `include!`-ed into both stallone-common and stallone-parsing to generate the
// needed data structures. This function calls a `generate!` macro which can be defined differently
// everywhere this is included. This macro approach has the added benefit of making it easier to
// generate other additional methods that we were writing by hand (like reading the data structures
// from an object file). Like I said, this is a bit dirty, but at least it's commonly used in C
// https://en.wikipedia.org/wiki/X_Macro

// We manually (as opposed to doing some automatic scheme) specify both the borrowed and owned
// versions of each type: `borrowed | owned`. In addition, since we need to compute the hash of
// these structures at compile-time, but Rust doesn't yet support const fn in traits, we manually
// specify, for each field, how we could hash it (if we can't hash it with .hash()).

generate! {
    #[mod_name = log_record_metadata]
    struct LogRecordMetadata<'a> {
        #[const_hash_with(HashU64)]
        magic_number: u64 | u64,
        hash_value: LogRecordMetadataHash | LogRecordMetadataHash,
        log_record_metadata_info: LogRecordMetadataInfo<'a> | LogRecordMetadataInfo,
    }
}

generate! {
    #[mod_name = log_record_metadata_info]
    struct LogRecordMetadataInfo<'a> {
        #[serde(with = "level_serde")]
        level: Level | Level,
        #[const_hash_with(HashStr)]
        message: &'a str | String,
        #[const_hash_with(HashStr)]
        file: &'a str | String,
        #[const_hash_with(HashStr)]
        module_path: &'a str | String,
        #[const_hash_with(HashStr)]
        cargo_pkg_version: &'a str | String,
        #[const_hash_with(HashU64)]
        line: u64 | u64,
        #[const_hash_with(HashU64)]
        column: u64 | u64,
        #[slice_const_hash(true)]
        fields: &'a [LogRecordMetadataField<'a>] | Vec<LogRecordMetadataField>,
    }
}
generate! {
    #[mod_name = record_type_field]
    struct RecordTypeField<'a> {
        #[const_hash_with(HashStr)]
        name: &'a str | String,
        ty: &'a ValueType<'a> | Box<ValueType>,
    }
}
generate! {
    #[mod_name = record_type]
    struct RecordType<'a> {
        #[const_hash_with(HashStr)]
        name: &'a str | String,
        #[slice_const_hash(true)]
        fields: &'a [RecordTypeField<'a>] | Vec<RecordTypeField>,
    }
}
generate! {
    #[mod_name = log_record_metadata_field]
    struct LogRecordMetadataField<'a> {
        #[const_hash_with(HashStr)]
        name: &'a str | String,
        type_id: &'a ValueType<'a> | Box<ValueType>,
        #[const_hash_with(HashU8)]
        is_context: u8 | bool,
    }
}
generate! {
    #[mod_name = log_record_metadata_hash]
    #[derive(Hash, Copy)]
    struct LogRecordMetadataHash {
        // SipHash(log record type) (64 bits)
        #[const_hash_with(HashU64)]
        schema_hash: u64 | u64,
    }
}
generate! {
    #[mod_name = stallone_type]
    enum ValueType<'a> {
        Bool,
        U8,
        U16,
        U32,
        U64,
        U128,
        I8,
        I16,
        I32,
        I64,
        I128,
        Char,
        String,
        Array {
            #[const_hash_with(HashU64Ref)]
            length: u64 | u64,
            contents: &'a ValueType<'a> | Box<ValueType>,
        },
        Vector { contents: &'a ValueType<'a> | Box<ValueType> },
        MultiMap {
            key: &'a ValueType<'a> | Box<ValueType>,
            value: &'a ValueType<'a> | Box<ValueType>,
        },
        Record { contents: RecordType<'a> | RecordType },
        Enum {
            #[const_hash_with(HashStr)]
            name: &'a str | String,
            #[slice_const_hash(true)]
            variants: &'a [RecordType<'a>] | Vec<RecordType>,
        },
    }
}

