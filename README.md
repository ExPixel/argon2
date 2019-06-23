Argon2 Bindings
===

[![Build Status](https://dev.azure.com/expixel/Argon2/_apis/build/status/ExPixel.argon2?branchName=master)](https://dev.azure.com/expixel/Argon2/_build/latest?definitionId=1&branchName=master)
[![crates.io](https://img.shields.io/crates/v/just-argon2.svg?color=orange)](https://crates.io/crates/just-argon2)
[![docs.rs](https://img.shields.io/badge/docs-stable-blue.svg)](https://docs.rs/just-argon2/1.0.0/argon2/)

Bindings to the Argon2 C library for Rust. The C implementation can be found at [https://github.com/P-H-C/phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2)

**NOTE**: The crate exposed by this package is called `argon2` and not `just_argon2`

### Example Usage

```rust
fn main() {
    const HASHLEN: usize = 32;
    const SALTLEN: usize = 16;
    const PWD: &[u8]     = b"password";
    const PWDLEN: usize  = 8;

    // so these don't get out of sync
    assert_eq!(PWD.len(), PWDLEN);

    let t_cost      = 2;            // 1-pass computation
    let m_cost      = 1 << 16;      // 64 mebibytes memory usage
    let parallelism = 1;            // number of threads and lanes

    let mut hash1   = [0u8; HASHLEN];
    let mut hash2   = [0u8; HASHLEN];
    let mut salt    = [0u8; SALTLEN];
    let mut pwd     = [0u8; PWDLEN];

    // Copy the password string into the array.
    pwd.copy_from_slice(PWD);

    // High-level API
    argon2::i_hash_raw(t_cost, m_cost, parallelism, Some(&mut pwd), Some(&mut salt), &mut hash1).expect("Error hashing using high-level API.");

    // Low-level API
    let mut context = argon2::Context {
        out:        &mut hash2,
        pwd:        Some(&mut pwd),
        salt:       Some(&mut salt),
        secret:     None,
        ad:         None,
        t_cost:     t_cost,
        m_cost:     m_cost,
        lanes:      parallelism,
        threads:    parallelism,
        version:    argon2::Version::Version13,
        flags:      argon2::Flags::DEFAULT,
    };
    argon2::i_ctx(&mut context).expect("Error hashing using low-level API.");

    assert_eq!(&hash1[0..], &hash2[0..], "Hashes do not match.");

    println!("Hashes match.");
}
```
