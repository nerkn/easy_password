Updated Easy password hashing



Supported algorithms:
- Bcrypt

Motivation
==========

Orginal library (https://github.com/ChrisPWill/easy_password) wont compile so I cloned and updated libraries.

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

License
=======
MIT License
