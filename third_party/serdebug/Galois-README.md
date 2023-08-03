It's come to this...

We want to be able:

1. to pretty-print values that we serialize, in a way that preserves the fact that we have enums and structs, for example. This excludes almost every serde format.
2. We want to support u128/i128 integers. This excludes the remaining formats.

The `serdebug` crate has the minimum delta to get it working with `{i,u}128`