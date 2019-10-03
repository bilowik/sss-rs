# sss-rs
[![Build Status](https://travis-ci.com/bilowik/sss-rs.svg?branch=master)](https://travis-ci.com/bilowik/sss-rs)

An implementation of a secret sharing scheme in Rust. 
This is not meant to be a serious/optimized implementation, it's more of a fun project to further
my Rust knowledge.

# Some things to note:
 - Finite field arithmetic has been reimplemented with GF(256) vs modulo a prime, however this has lead to
   a decrease in Share speed by a factor of 4 (since we are working on bytes vs u32). Reconstruction speed
   is surprisingly marginally faster? Hooray! Also secret sizes are now equal to the original file size 
   rather than twice the size, which is another win!
   	- This also comes with a vast number of other improvements as well, and prevents several major issues
		- An overflow could occur when calculating the y-value when the number of shares exceeded 10
			- Shares are now only limited by u8, so [2, 255] 
		- Excess bytes that don't fit into a u32 did not effectively have their polynomials hidden via
			finite field arithmetic since the point sizes would always be below the prime
 - While the example only showcases File's as input, but a more general method is available that 
   accepts any Readable sources, as well as Writeable dest for sharing.
   	- Note: Generic Writeble secret destination for reconstruction is planned for 0.6.0

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
sharer.share_to_files(dir, stem).unwrap();
let recon = Sharer::reconstructor(dir, stem, num_shares).unwrap();
assert_eq!(secret, *recon_secret);


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
