# sss-rs
[![Build Status](https://travis-ci.com/bilowik/sss-rs.svg?branch=master)](https://travis-ci.com/bilowik/sss-rs)

An implementation of a secret sharing scheme in Rust. 

**wrapped_sharing** contains wrapper functions that wrap around the functionality in **basic_sharing**, which 
can include using a hash placed at the end to automatically verify if the secret was properly reconstructed,
ease of 'compressing' the shares by not requiring an X-value for every Y-value, and sharing/reconstructing to
and from memory and files interchangeably.

This implementation uses arithmetic over GF(256), shares using **wrapped_sharing** use a 64-byte hash placed
at the end of the of the secret before sharing that gets shared with it. This way, the 
reconstruction of the secret can be verified by the hash. This along with a share's corresponding
X-value, puts each share at [[1-byte X value]] + [[N-byte Secret]] + [[64-byte hash (optional)]]

Notably, given N required shares to reconstruct, and M shares generated, any X number of shares where
N <= X <= M can be used, without the need of specifying how many were required (using more shares however 
will increase reconstruction time). This goes for both **wrapped_sharing** and **basic_sharing**.


## Example with the wrapped_sharing API
```rust
use wrapped_sharing::{Secret, share};
let shares_required = 3;
let shares_to_create = 3;
let verify = true;
let secret: Vec<u8> = vec![5, 4, 9, 1, 2, 128, 43];
let shares = share(Secret::InMemory(secret), shares_required, shares_to_create, verify).unwrap();
let mut recon = Secret::empty_in_memory();
reconstruct(&mut recon, shares);
assert_eq!(secret, recon.unwrap_vec());
```


## Example with the lower-level basic_sharing API
```rust
use basic_sharing::{from_secret, reconstruct_secret};
// While this just uses a single secret sharing function, there are variants for Vec<u8>
let mut rand = SmallRng::seed_from_u64(123u64); // Note that rng is optional, default seeds from entropy
let secret: u8 = 23; // The secret to be split into shares
let shares_required = 3; // The number of shares required to reconstruct the secret
let shares_to_create = 3; // The number of shares to create, can be greater than the required

let shares: Vec<(u8, u8)> = from_secret(secret,
							shares_required,
							shares_to_create,
							Some(rand)).unwrap();
let secret_recon = reconstruct_secret(shares);

assert_eq!(secret, secret_recon);
```
