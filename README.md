# sss-rs
A purely functional (as in, working) and likely inefficient implementation of Shamir Secret Sharing in Rust

Not intended to be used in production code in ANY way, I do not provide any guarantees for data that
may be stored using the library provided here. Use at your own risk.

# Example
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

