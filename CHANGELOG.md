## sss-rs 0.13.0 04/27/2025
### General
- More test coverage, specifically utilizing itertools to ensure that every X subset of Y shares can correctly reproduce the secret
- An additional fuzz test which specifically tests sharing and reconstructing some secret with X required shares, 255 shares created, and Y shares used for
reconstruction where 2 <= X <= 255 and X <= Y <= 255. 
- X-values generated for shares are not fully random and not incremental. 
- Removal of various previously-deprecated functions.

### Wrapped sharing
- (Potentially Breaking) Removed generic T param from Reconstructor to put it in line with the Sharer.
  - The generic parameter is instead defined on the `new()` method. Usage of the `new()` method is unchanged 
    so this is only breaking if you explicitly utilized the `Reconstructor<T>` when defining a variable or argument. 
- X-values used in share generation will be randomized (since this utilizes functionality from basic_sharing)

### Basic sharing
- Randomly generate the X-values used during share generation, as opposed to incremental X-values.
  - This provides less information to an attacker, but it also entirely backwards compatible with previously 
    generated shares. 

## sss-rs 0.12.0 06/17/2023
Bumping due to a few missing deprecation notices and some likely-backwards-compatible generics improvements. There
was also the unhandled case where 0 shares were sent to reconstruct_secrets and would cause a panic, so it's call
signature had to be changed to Result, which is a breaking change.

### General
- Better test coverage
- A fuzzing test to poke around for edge cases (behind the feature flag "fuzz_tests")

### Wrapped sharing
- Deprecate a few old functions that were missed in 0.11.0. 
- Checks for number of share outputs/inputs for Sharer/Reconstructor to ensure reconstruction is possible and
  avoids a u8 overflow panic
- Wrappers around Sharer/Reconstructor for the common use case of iterating over buffered reads/writes. These
  are very similar to the deprecated share_to_writeables/reconstruct_from_srcs but are more efficient and handle
  errors more gracefully.

### Basic Sharing
- Remove Error::EmptySecretArray, was unused and sharing an empty array is technically valid, although serves no 
  purpose.
- Change the call signature of reconstruct functions to Result<...> to avoid a panic when 0 shares are passed to them.



## sss-rs 0.11.0 06/12/2023
A lot of cleanup, a lot of optimizations on all fronts. Most breaking changes occur in just `wrapped_sharing`, `basic_sharing` is relatively untouched in terms of API aside from added generics that should accept all previous usages aside from two function renames.

### General
- Removed a lot of old code that was no longer in use, including a lot of the `geometry` module from back before the migration to using finite field arithmetic.
- Lots of new documentation, lots of cleanup of old documentation.
- Implemented the "rayon" feature to enabling parallel sharing/reconstructing. Enabled by default.
- Added new criterion-based benchmarks, to compare performance against 0.10.1, I added those same benchmarks to a branch based on 0.10.1 callled `v0.10.1_with_benches` which includes just the basic_sharing benches since wrapped_sharing is not very equitable to its 0.10.1 version.

### Wrapped sharing
- Deprecated most of the original sharing `wrapped_sharing` functions
- Added new, much cleaner `share`/`reconstruct` functions. 
- Added infinitely more useful, optimized, cleaner `Sharer` and `Reconstructor` structs for large files or streams, compared to the old multitude of share/reconstruct functions that sought to handle those cases.
   - Heavily inspired by sha3 hash implementation :) 
- Remove old `Error` variants that are no longer instantiated.
   - This was missed by linters, they were only ever accessed in the Display impl but never directly instantiated anymore. 

### Basic sharing
- Completely remove reliance of the very inefficient matrix transposition required when sharing slices of bytes. Included a lot of cloning, a lot of Vec allocations. The benchmark improvements from this alone were ~30%, and for very large secrets >=65536 bytes, a ~90% improvement. 
  - The time for sharing and reconstructing now also scales very very linearly with the length of secret! 
- Added parallelization, further improving performance for payloads > 4096 in size.
- Renamed the `from_secrets_no_points` and `reconstruct_secrets_no_points` by replacing `_no_points` with `_compressed`
- Cleaned up a lot of unneeded allocations
- Replaced all argument instances of `&[u8]`  and `Vec<u8>` with `AsRef<[u8]>`
- Replaced all argument instances of `Vec<Vec<u8>>` with `U: AsRef<[u8]>, T: AsRef<[U]>`
- Remove old `Error` variants that are no longer instantiated.
   - This was missed by linters, they were only ever accessed in the Display impl but never directly instantiated anymore. 


## sss-rs 0.10.1 06/05/2023
 - Fix an issue where the hash length was not being calculated correctly during reconstruction
   - This is mostly for correctness and for debugging. The only time this issue would be noticeable is if 
     an shorter `src_len` than expected was provided during reconstruction, which would result in more than
     the final 64-bytes being pulled for hash comparison. 
 - Dependency update and cleanup


## sss-rs 0.10.0 02/15/2023
 - Breaking changes, but for the sake of MUCH simpler usage
 - Deprecate `Secret`, it is no longer required to use the library, but can still be used for compatibility.
 - `share()` and `reconstruct()` have been renamed to `share_from_buf()` and `reconstruct_to_buf()` respectively
    - They also now take a generic T for any `T: Read + Seek` for sharing and `T: Read + Write + Seek` for reconstructing. This
      includes the now deprecated Secret enum which implements these traits.
 - Implement new, straightforward-to-use `share()` and `reconstruct()` functions (see README.md for example usage)

## sss-rs 0.9.1 07/25/2022
 - Avoid reseeding from entropy when no rng is specified when sharing
    - Depending on the source of the entropy this may make sharing 
	  noticeably faster.

## sss-rs 0.9.0 07/09/2021
 - Move out reconstruction functions out of Secret impl block, for consistency with the sharing 
   functions.
   	- reconstruct, reconstruct_from_srcs no longer belong to Secret struct and instead take
	  it as its first argument.
 - RustFmt pass, have not used RustFmt up to this point, and fixed a lot of non-idiomatic code.

## sss-rs 0.8.1 09/06/2021
 - Remove rust-crypto dependency since it is no longer maintained (thank you umgefahren for pointing that out to me)
 - Fix improper license setting in Cargo.toml that caused it to be listed as non-standard in crates.io

## sss-rs 0.8.0 03/27/2021
 - Rework wrapped_sharing to use wrapped_sharing::Error instead of returning Box\<dyn Error> 
   so it can be matched against to gain more information. This *shouldn't* be a breaking change, 
   but the API did change. 

## sss-rs 0.7.2 10/12/2020
 - Add 'verifiable' flag to sharing/reconstruction functions in wrapped_sharing
 	- This allows the use of wrapped_sharing without being forced to place a verfiable hash at
	  the end of the shares.
	- Developer Note: It was a bit of an oversight to assume verifiable sharing be not optional.
	  There are definitely situations where one would not want the reconstruction to be verifiable.

## sss-rs 0.7.1 07/16/2020
 - Update README.md to reflect recent 0.7.0 changes


## sss-rs 0.7.0 07/14/2020
 - A LOT of cleanup:
 	- Documentation formatting cleaned up and made more consistent
	- References to old arguments/api removed
	- Made geometry and utils module private
	- Removed re-exports of both primary modules to avoid confusion between their functions
### sharer.rs **(Renamed to wrapped_sharing.rs)**
 - Removed 'Sharer' struct and moved its functionality to standalone functions, similar to raw_share
 - Shares generated by sharer functions are now (secret length) + (hash length) **+ 1** due to the 
   first byte of every share being the corresponding X value for those share points.
 - Simplified Sharer Usage:
	- Made base share/reconstruct functions use Vec's
	- Path-related args now properly ask for AsRef<Path>
	- Added many convenient unwrap methods for Secret to get the bytes.
 - MAJOR bug fix regarding sharer share reconstruction, if they were to be reconstructed out of order,
   or if more shares were generated than needed and only the required but out-of-order shares were 
   used, would cause incorrect reconstruction.
   	- Now, if you generate with N shares, M required for reconstruction, then any X number of shares, 
	  M <= X <= N, and in any order, can be used for reconstruction. (This goes for raw_share functions
	  as well)
### raw_share.rs: **(Renamed to basic_sharing.rs)**:
 - Greatly shortened names
 - Sharing functions have also been added to raw_share that include some of this functionality 
   regarding putting the x value at the front of the share's y-values. They are listed as 
   "no_points" variants of the raw_share functions.
 - Removed "custom_rng" wrapper for raw_share functions
	- Since it was just one additional parameter, a simple Option made more sense
 - Removed shuffle operations, since they served little purpose other than novelty


## sss-rs 0.6.1 11/27/2019
 - Updated rand and chacha deps to 0.7.2 and 0.2.1 respectively


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
