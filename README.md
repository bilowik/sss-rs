# sss-rs
[![Rust](https://github.com/bilowik/sss-rs/actions/workflows/rust.yml/badge.svg?branch=master)](https://github.com/bilowik/sss-rs/actions/workflows/rust.yml)

An implementation of a secret sharing scheme in Rust. 

Given N required shares to reconstruct, and M shares generated, any X number of shares where
N <= X <= M can be used, without the need of specifying how many were required (using more shares however 
will increase reconstruction time). 

There are two primary modules, [wrapped_sharing] and [basic_sharing]. [basic_sharing] holds the core secret sharing
implementation, and [wrapped_sharing] provides convenience wrappers around those implementations as well as the 
option to verify reconstruction of the secret.

This implementation uses arithmetic over GF(256) for the core secret sharing algorithm. 



## Examples
### 
```rust
use sss_rs::wrapped_sharing::{share, reconstruct};
let shares_required = 3;
let shares_to_create = 3;
let verify = true;
let secret: Vec<u8> = vec![5, 4, 9, 1, 2, 128, 43];
let shares = share(&secret, shares_required, shares_to_create, verify).unwrap();
let recon = reconstruct(&shares, verify).unwrap();
assert_eq!(secret, recon);
```


## Example with the lower-level basic_sharing API
```rust
use sss_rs::basic_sharing::{from_secret, reconstruct_secret};
let secret: u8 = 23; // The secret to be split into shares
let shares_required = 3; // The number of shares required to reconstruct the secret
let shares_to_create = 3; // The number of shares to create, can be greater than the required

let shares: Vec<(u8, u8)> = from_secret(
		secret,
		shares_required,
		shares_to_create,
        None,
	).unwrap();
let secret_recon = reconstruct_secret(shares);

assert_eq!(secret, secret_recon);
```


