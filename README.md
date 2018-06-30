# vimdecrypt-rs

A rust library and command line tool to read encrypted Vim files.
The crate comes with a simple public API and a simple CLI tool.

As Vim needs to keep all files it edits in memory, this crate operates on the assumption that this is feasible, i.e. it does not provide a streaming API.

## API

The API consisting of a single function that decodes a block of bytes given a password, which has to be valid UTF-8. A simple function to encode a file by its path might look like this:

```rust
fn decrypt_file(filename: &str) -> String {
    let data = fs::read(filename).unwrap();
    const PASSWORD: &str = "blubberfish";
    vimdecrypt::decrypt(&data, &PASSWORD).expect("Decryption failed.")
}
```

# License

vimdecrypt-rs is distributed under the terms of both the MIT license and the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
