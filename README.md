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



# Examples
## Abstractions
### Functional wrapped API
Useful for working with relatively small secrets.
```rust
use sss_rs::prelude::*;
let shares_required = 3;
let shares_to_create = 3;
let verify = true;
let secret: Vec<u8> = vec![5, 4, 9, 1, 2, 128, 43];
let shares = share(&secret, shares_required, shares_to_create, verify).unwrap();
let recon = reconstruct(&shares, verify).unwrap();
assert_eq!(secret, recon);
```

### Streaming wrapped API
Useful for working with very large secrets and shares that you don't want all loaded into
memory at once. 
```rust
use sss_rs::prelude::*;
use std::io::Cursor;

let mut dest1 = Cursor::new(Vec::new());
let mut dest2 = Cursor::new(Vec::new());
let full_secret = b"This is a very long secret read in from a buffered file reader";
let secret_chunks = full_secret.chunks(8).collect::<Vec<&[u8]>>();
let mut recon_dest = Cursor::new(Vec::new());

let mut sharer = Sharer::builder()
    .with_shares_required(2)
    .with_output(&mut dest1)
    .with_output(&mut dest2)
    .with_verify(true)
    .build()
    .unwrap();

for secret in secret_chunks.iter() {
    sharer.update(secret).unwrap();
}
sharer.finalize().unwrap();

// The outputs dest1 and dest2 have had their shares written to them.

let mut reconstructor = Reconstructor::new(&mut recon_dest, true);

for (chunk1, chunk2) in dest1.get_ref().chunks(4).zip(dest2.get_ref().chunks(4)) {
    reconstructor.update(&[chunk1, chunk2]).unwrap();
}
reconstructor.finalize().unwrap();
assert_eq!(&full_secret, &recon_dest.into_inner().as_slice());
```

## Core

### Single-byte 
If you need more control over sharing and reconstruction or write your own
abstractions, the [basic_sharing] functions can be used.

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

### Slice of bytes
Very similar to the above example but works on slices of bytes.
```rust
use sss_rs::basic_sharing::{from_secrets, reconstruct_secrets};
let secret = b"Hello world"; // The secret to be split into shares
let shares_required = 3; // The number of shares required to reconstruct the secret
let shares_to_create = 3; // The number of shares to create, can be greater than the required

let shares: Vec<Vec<(u8, u8)>> = from_secrets(
		secret,
		shares_required,
		shares_to_create,
        None,
	).unwrap();
let secret_recon = reconstruct_secrets(shares);

assert_eq!(secret, secret_recon.as_slice());
```

### Slice of bytes deduped x values
Also very similar to the above example but will dedup the x-value of each share and place it
at the beginning of each list of shares. All functionality in [wrapped_sharing] utilizes this.
There is an explanation below that describes how and why this works in more detail.
```rust
use sss_rs::basic_sharing::{from_secrets_compressed, reconstruct_secrets_compressed};
let secret = b"Hello world"; // The secret to be split into shares
let shares_required = 3; // The number of shares required to reconstruct the secret
let shares_to_create = 3; // The number of shares to create, can be greater than the required

let shares: Vec<Vec<u8>> = from_secrets_compressed(
		secret,
		shares_required,
		shares_to_create,
        None,
	).unwrap();
let secret_recon = reconstruct_secrets_compressed(shares);

assert_eq!(secret, secret_recon.as_slice());
```


# Sharing and share 'compression' explanation
```notrust
N = Number of shares required for reconstruction
M = Number of shares that were created
S = Length of the secret being shared.
```
Usually, a list of points is needed for the reconstruction of a byte.
`(x1, y1), (x2, y2), (x3, y3), ... (xM, yM)` 
where at least N number of points from the M created points are needed to reconstruct the byte.
Each share is **twice** as large as the original secret.

When we share a slice of bytes, we get lists of shares like this:

```notrust
(x1a, y1a), (x2a, y2a), (x3a, y3a), ... (xMa, yMa)
(x1b, y1b), (x2b, y2b), (x3b, y3b), ... (xMb, yMb)
(x1c, y1c), (x2c, y2c), (x3c, y3c), ... (xMc, yMc)
...
(x1S, y1S), (x2S, y2S), (x3S, y3S), ... (xMS, yMS)
```

Each of the above list of points corresponds to just 1 byte of the secret. For example, any N points from 
the first list will reconstruct the first byte of the secret. 
These cannot be distrubted this way, since each share corresponds to one byte, rather than one piece 
of the whole secret. So, we transpose this, so every list has one piece of every byte of the secret.

```notrust
(x1a, y1a), (x1b, y1b), (x1c, y1c), ... (x1S, y1S)
(x2a, y2a), (x2b, y2b), (x2c, y2c), ... (x2S, y2S)
(x3a, y3a), (x2b, y2b), (x3c, y3c), ... (x3S, y3S)
...
(xMa, yMa), (xMb, yMb), (xMc, yMc), ... (xMS, yMS)
```

Now with a given index, the byte of the secret at that index can be reconstructed from at least N shares. For example,
to reconstruct the 3rd byte of the secret, you need the third point from at least N shares to reconstruct. Now everyone has
a list of points where each point corresponds to just 1 byte of the original secret. These can now be distributed.

Moving onto the compression, the x values can be predictable without a significant impact to the security of the shares.
This is what the list of shares prior to transposition look like with predictable x-values.

```notrust
(1, y1a), (2, y2a), (3, y3a), ... (M, yMa)
(1, y1b), (2, y2b), (3, y3b), ... (M, yMb)
(1, y1c), (2, y2c), (3, y3c), ... (M, yMc)
...
(1, y1S), (2, y2S), (3, y3S), ... (M, yMS)

And when we transposed for the reasons stated prior to make these shares distributable:

```notrust
(1, y1a), (1, y1b), (1, y1c), ... (1, y1S)
(2, y2a), (2, y2b), (2, y2c), ... (2, y2S)
(3, y3a), (3, y3b), (3, y3c), ... (3, y3S)
...
(M, yMa), (M, yMb), (M, yMc), ... (M, yMS)
```

We can see the x values for every point in a given share is identical. So we can dedup that x-value and 
have one copy of it at the beginning of each share.

```notrust
1, y1a, y1b, y1c, ... y1S
2, y2a, y2b, y2c, ... y2S
3, y3a, y3b, y3c, ... y3S
...
M, yMa, yMb, yMc, ... yMS
```

Which brings the size of each share to just S + 1 compared to S * 2 previously. 
