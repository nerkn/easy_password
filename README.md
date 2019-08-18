Easy password hashing

Supported algorithms:
- Bcrypt

Motivation
==========
Using Bcrypt as is results in passwords being limited to a length of 72. This
means it's not easy to salt the password or support arbitrarily long user
passwords.

This library performs a [HMAC](https://en.wikipedia.org/wiki/HMAC) with SHA256
used as the hash function before feeding the result into Bcrypt. As such, any
length of password can be used with Bcrypt when passwords are made or verified
with this library.

Usage
=====
Hashing a password:

```rust
extern crate easy_password;

use easy_password::bcrypt::hash_password;

let bcrypt_rounds = 12; // Secure default
let hash: String =
    hash_password("my_password", b"secure_key", 12).unwrap();
```
Verifying a hash:

```rust
extern crate easy_password;

use easy_password::bcrypt::hash_password;

let success: bool =
    verify_password("test_password", hash.as_str(), b"secure_key").unwrap();
```

Linting Code
------------

Install clippy:
```
rustup component add clippy
```

To lint the code:
```
cargo clippy
```

Apply all suggested refactorings (don't forget to reformat code)

Formatting Code
---------------

Note: Currently the nightly version of rustfmt is used for formatting purposes only. The project
itself is written and tested on the most current version of stable Rust.

To install rustfmt:
```
rustup component add rustfmt --toolchain nightly
```
To format the code:
```
cargo +nightly fmt
```

License
=======
MIT License, see LICENSE
