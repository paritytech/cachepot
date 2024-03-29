# caveats

## rustc

cachepot includes support for caching Rust compilation. This includes many caveats, and is primarily focused on caching rustc invocations as produced by cargo. A (possibly-incomplete) list follows:

* `--emit` is required in order to produce dependency information
* `--crate-name` is required
* Only `link` and `dep-info` are supported as `--emit` values, and `link` must be present
* `--out-dir` is required
* `-o file` is not supported
* Compilation from stdin is not supported, a source file must be provided
* Values from `env!` will not be tracked in caching
* Procedural macros that read files from the filesystem may not be cached properly
* Target specs aren't hashed (e.g. custom target specs)

If you are using Rust 1.18 or later, you can ask cargo to wrap all compilation with cachepot by setting `RUSTC_WRAPPER=cachepot` in your build environment.
