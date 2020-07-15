# sss-rs
[![Build Status](https://travis-ci.com/bilowik/sss-rs.svg?branch=master)](https://travis-ci.com/bilowik/sss-rs)

An implementation of a secret sharing scheme in Rust. 

The Sharer and Secret structs are simply wrappers around raw_share that provide some convenience.

This implementation uses arithmetic over GF(256), shares using **Sharer** use a 64-byte hash placed
at the end of the of the secret before sharing that gets shared with it. This way, the 
reconstruction of the secret can be verified by the hash. This along with a share's corresponding
X-value, puts each share at [[1-byte X value]] + [[N-byte Secret]] + [[64-byte hash]]

Notably, given N required shares to reconstruct, and M shares generated, any X number of shares where
N <= X <= M can be used, without the need of specifying how many were required (using more shares however 
will increase reconstruction time). This goes for both Sharer and raw_share. 

## Example with the Sharer API
```rust
let num_shares = 3;
let secret: Vec<u8> = vec![5, 4, 9, 1, 2, 128, 43];
let sharer = Sharer::builder(secret.clone())
	.shares_required(num_shares) // Default is 3 if not explicitly set
	.shares_to_create(num_shares)// Default is 3 if not explicitly set
	.build()
	.unwrap();
let shares = sharer.share().unwrap();
let mut recon = Secret::empty_in_memory();
recon.reconstruct(shares);
assert_eq!(secret, recon.unwrap_vec());
```


## Example with the lower-level raw_share functional API
```rust
let mut rand = SmallRng::seed_from_u64(123u64); // Note that rng is optional, default seeds from entropy
let secret: u8 = 23; // The secret to be split into shares
let shares_required = 3; // The number of shares required to reconstruct the secret
let shares_to_create = 3; // The number of shares to create, can be greater than the required

let shares: Vec<(u8, u8)> = create_shares_from_secret(secret,
							shares_required,
							shares_to_create,
							Some(rand)).unwrap();
let secret_recon = reconstruct_secret(shares);

assert_eq!(secret, secret_recon);
```
