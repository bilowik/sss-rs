## sss-rs 0.6.0 11/27/2019
 - Added functions to raw_share that allow for custom RNGs for coefficient generation
 	- It should be noted that using predictable RNG can lead to a loss of unconditional security,
		so use with caution

## sss-rs 0.5.0 10/02/2019
 - Re-enabled finite field arithmetic via GF(256)
 	- A decrease in share creation speed by a factor of 4 (since we are processing bytes vs u32s)
	- Reconstruction speed has remained the same.
 	- Shares are now the same size as the secret
	- When shares exceed 10 there's no longer a chance at an multiplication overflow
	- Secrets with len % 4 != 0 no longer have trailing bytes not properly shared with finite field 
		arithmetic due to points' y-values never being larger than the prime
		- All bytes in general are now guaranteed to be properly shared via finite field arithmetic
	- Reconstruction and share speed do not scale linearly with the number of shares (citation needed)

## sss-rs 0.4.0 09/29/2019
 - Segmented reading/processing of secrets and shares
	- For all secrets/shares, they are read in chunks of 8KB, which had shown to give the best 
	 performance
 	- This greatly reduces the memory footprint and is a general perforamnce improvement
 - 4-byte secret processing
 	- Secrets are now processed in chunks of 4-bytes vs 1-byte, which gave major perforamnce 
	  improvements.
	- For secrets with length not divisible by 4, are processed in single bytes, no padding!
 - Temporarily disabled finite field arithmetic via primes
 	- Note: My knowledge of how finite field arithmetic worked seemed to be off, and was never 
	working as intended, so has been disabled until I can properly implement it back in. The API
	remains the same however, it accepts primes but does nothing with them.

## sss-rs 0.3.1 09/22/2019
 - Tests were making use of the same dir and stem, and since Rust unit tests are run in multiple threads by default, this caused occasional test failures when the two tests happened to be running at the same time. The test files are now named based on the name of the test to prevent this issue again

## sss-rs 0.3.0 09/21/2019
 - Sharer struct: Wrapped the original, function-only API with an struct with builder style construction with sane defaults.
 	- Handles sharing and reconstruction of shares. 
	- Output shares to files with just a stem and a dir
	- Output share N to a generic Write destination
	- Test the reconstruction to ensure the secret can be recreated.
 	- A default prime number is an option, since keeping the prime a secret is not technically necessary.
	
## sss-rs 0.2.0 09/17/2019
 - The main shuffle function now takes an arbitrary number of bytes instead of a password. Forcing a 
 specific hashing algorithm to be used was restrictive and inflexible, and using a trait object, while 
 better, would still restrict hashing algorithms to ones ported to Rust or wrapped in Rust code. 
 	- However since the seed must be 32 bytes, the hash will be sent through SHA256 to produce a 
	32-byte hash. This has little impact on the security of the initial hashing algorithm.

## sss-rs 0.1.1 09/16/2019
 - Fixed Rust stable compilation error regarding enum variants on type aliases
 	- In the Display impl for the Error enum, its variants were referenced as Self:: instead of Error::
	  which caused compilation issues on Rust's current stable version 1.36.0


## sss-rs 0.1.0 09/15/2019
 - Initial version 
