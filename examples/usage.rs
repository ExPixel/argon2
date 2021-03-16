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

    assert_eq!(&hash1[..], &hash2[..], "Hashes do not match.");

    println!("Hashes match.");
}
