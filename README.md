# sss-rs
[![Build Status](https://travis-ci.com/bilowik/sss-rs.svg?branch=master)](https://travis-ci.com/bilowik/sss-rs)

An implementation of a secret sharing scheme in Rust. 
This is not meant to be a serious/optimized implementation, it's more of a fun project to further
my Rust knowledge.


# New Example with the current API
```
let dir = "./";
let stem = "test";
let num_shares = 3;
let secret: Vec<u8> = vec![5, 4, 9, 1, 2, 128, 43];
let sharer = Sharer::builder(secret)
	.shares_required(num_shares) // Default is 3 if not explicitly set
	.shares_to_create(num_shares)// Default is 3 if not explicitly set
	.build()
	.unwrap();
let shares = sharer.share().unwrap();
let mut recon = Secret::empty_in_memory();
recon.reconstruct(shares);
assert_eq!(secret, recon);


```


# Old Example (makes use of raw_share functions)
```
let mut rand = SmallRng::seed_from_u64(123u64);
let secret: u8 = 23; // The secret to be split into shares
let shares_required = 3; // The number of shares required to reconstruct the secret
let shares_to_create = 3; // The number of shares to create, can be greater than the required
let bit_size_co: usize = rand.gen_range(32, 65); // The number of bits for the generated coefficients

let shares: Vec<(u8, u8)> = create_shares_from_secret(	secret,
							shares_required,
							shares_to_create).unwrap();
let secret_recon = reconstruct_secret(shares);

assert_eq!(secret, secret_recon);
```

# TODO:
	- The shuffle operation was left out of the new API, mainly because it would not function after the 
	  above change is implemented. May re-implement a way to shuffle the data in-file. For now this 
	  will be benched.
