# sss-rs
[![Build Status](https://travis-ci.com/bilowik/sss-rs.svg?branch=master)](https://travis-ci.com/bilowik/sss-rs)

A purely functional (as in, working) and likely inefficient implementation of a Secret Sharing Scheme in Rust

Not intended to be used in production code.

# New Example with the current API
```
let dir = "./";
let stem = "test";
let num_shares = 3;
let secret: Vec<u8> = vec![5, 4, 9, 1, 2, 128, 43];
let sharer = Sharer::builder(secret)
	.shares_required(num_shares)
	.shares_to_create(num_shares)
	.coefficient_bits(32)
	.build()
	.unwrap();
sharer.share_to_files(dir, stem).unwrap();
let recon = Sharer::reconstructor(dir, stem, num_shares, PrimeLocation::Default).unwrap();


```


# Old Example (makes use of raw_share functions)
```
let mut rand = SmallRng::seed_from_u64(123u64);
let secret: u8 = 23; // The secret to be split into shares
let shares_required = 3; // The number of shares required to reconstruct the secret
let shares_to_create = 3; // The number of shares to create, can be greater than the required
let bit_size_co: usize = rand.gen_range(32, 65); // The number of bits for the generated coefficients
let prime_bits: usize = rand.gen_range(bit_size_co + 128, 257); // The number of bits for the prime
let mut prime: BigInt = rand.gen_prime(prime_bits).into(); // The prime number used for finite field
while prime < BigUint::from(secret) {
	// In case the prime is less than the secret, generate new ones until one is greater
	prime = rand.gen_prime(prime_bits).into();
}

let shares: Vec<Point> = create_shares_from_secret(	secret,
							&prime
							shares_required,
							shares_to_create,
							bit_size_co).unwrap();
let secret_recon = reconstruct_secret(shares, &prime, shares_required).unwrap();

assert_eq!(secret, secret_recon);
```

# TODO:
 - Clean up modulo operations, figure out why when given two equal primes the result is not 0.
 - Add more testing to sharer.rs
