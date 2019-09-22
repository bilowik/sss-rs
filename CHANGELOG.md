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
