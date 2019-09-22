use crate::raw_share::*;
use crate::geometry::Point;
use rand::{Rng, FromEntropy};
use rand::rngs::StdRng;
use num_bigint_dig::{BigInt, BigUint, RandPrime};
use std::io::{Read, Write};
use std::error::Error;
use std::fs::File;
use std::path::Path;
use std::ops::Deref;
use lazy_static::lazy_static;
use crypto::sha3::Sha3;
use crypto::digest::Digest;

// constants
lazy_static! {
    pub static ref DEFAULT_PRIME: BigInt = BigInt::from(4173179203 as u32);
}

const NUM_FIRST_BYTES_FOR_VERIFY: usize = 32;



/// Defines a prime as either THE default prime, or a NonDefault one either generated or given
/// statically. If the default one is used it doesn't make sense to write it to a file
#[derive(Debug, Clone)]
enum Prime {
    Default(BigInt),
    NonDefault(BigInt),
}

/// Defines the location of the prime to the reconstructor, if it's the default prime, or if it was
/// saved to a file. InFile doesn't have any data since the file should always be the stem appended
/// with '.prime'
#[derive(Debug, Clone)]
pub enum PrimeLocation {
    InFile, // The prime file is location in a file and is not the default 
    Default, // The prime isn't in any file, the default prime was used.
}

impl Deref for Prime {
    type Target = BigInt;
    fn deref(&self) -> &Self::Target {
        match self {
            Prime::Default(prime) => &prime,
            Prime::NonDefault(prime) => &prime,
        }
    }
}

/// Creates shares from a given secret and reconstructs them back into the secret. 
#[derive(Debug)]
pub struct Sharer {
    share_lists: Vec<Vec<Point>>,
    secret: Vec<u8>,
    prime: Prime,
    shares_required: usize,
    verify: bool
}

/// The builder struct to give the Sharer struct  builder style construction. 
/// Defaults:
///     - prime: Prime::Default(<The default prime>)
///     - shares_required: 3
///     - shares_to_create: 3
///     - coefficient_bits: 32
#[derive(Debug)]
pub struct SharerBuilder {
    secret: Vec<u8>, // The secret to be shared 
    prime: Prime, // The prime number use to bring the underlying share polynomial into a finite field
    shares_required: usize, // The number of shares needed to reconstruct the secret
    shares_to_create: usize, // The number of shares to generate
    coefficient_bits: usize, // The number of bits the random coefficients of the polynomial will have.
    verify: bool,            // Whether or not to append a hash for verification to the end of the secret
}



impl Sharer {

    /// Constructs the builder with defualt values. See the builder documentation for the default
    /// values.
    pub fn builder(secret: Vec<u8>) -> SharerBuilder {
        SharerBuilder { secret: secret, 
                        ..Default::default()
        }
    }

    /// Shares a single share, designated by share_num, to a writable destination.
    /// This function will panic if share_num is greater than the number of shares created.
    pub fn share<T: Write>(&self, dest: &mut T, share_num: usize) 
        -> Result<(), Box<dyn Error>> {
        dest.write_all(&(self.share_lists[share_num].len() as u64).to_be_bytes())?;
        for share in &self.share_lists[share_num] {
            let bytes = share.y().get_numerator().to_signed_bytes_be();
            dest.write_all(&(bytes.len() as u32).to_be_bytes())?;
            dest.write_all(share.y().get_numerator().to_signed_bytes_be().as_slice())?;
        }
        Ok(())
    }

    /// Outputs the prime to a given writeable destination.
    pub fn share_prime<T: Write>(&self, dest: &mut T) -> Result<(), Box<dyn Error>> {
        dest.write_all(self.prime.to_signed_bytes_be().as_slice())?;
        Ok(())
    }

    /// Shares all the shares to separate files for distribution. 
    /// @stem: Defines the stem of the output files, they will be @stem.s0, @stem.s1, and so on..
    /// @dir: The directory to output the shares to. 
    pub fn share_to_files(&self, dir: &str, stem: &str) -> Result<(), Box<dyn Error>> {
       
        let file_paths = generate_share_file_paths(dir, stem, self.share_lists.len());
        for i in 0..file_paths.len() {
            let mut curr_file = File::create(&file_paths[i])?;
            self.share(&mut curr_file, i)?;
        }

        if let Prime::NonDefault(_) = &self.prime {
            let prime_file_path = generate_prime_file_path(dir, stem);
            let mut curr_file = File::create(prime_file_path)?;
            self.share_prime(&mut curr_file)?;
        }

        Ok(())
    }


    /// Tests the reconstruction of the shares as outputted via the @share_to_files function.
    /// @dir: The directory to output the temporary shares. Default is the current dir
    pub fn test_reconstruction_file(&self, dir: Option<&str>) -> Result<(), Box<dyn Error>> {
        let default_dir = "./";
        let dir = match dir {
            Some(dir_str) => dir_str,
            None => default_dir,
        };
        let stem = ".tmp_share_file";
    
        let prime_location = match self.prime {
            Prime::Default(_) => PrimeLocation::Default,
            Prime::NonDefault(_) => PrimeLocation::InFile,
        };



        self.share_to_files(dir, stem)?;

        let recon = Sharer::reconstructor(dir, 
                                          stem, 
                                          self.shares_required, 
                                          prime_location.clone(),
                                          self.verify)?;
        
        if recon.get_secret() != self.get_secret() {
            return Err(Box::new(SharerError::ReconstructionNotEqual));
        }

        let mut used_files = generate_share_file_paths(dir, stem, self.shares_required);
        if let PrimeLocation::InFile = prime_location {
            used_files.push(generate_prime_file_path(dir, stem));
        }
        for path in used_files {
            std::fs::remove_file(path)?;
        }

        Ok(())

    }

    /// Returns an immutable reference to the secret
    pub fn get_secret<'a>(&'a self) -> &'a [u8] {
        if self.verify {
            // The secret contains a hash at the end that is not a part of the secret
            &self.secret[0..self.secret.len() - 64]
        }
        else {
            &self.secret
        }
    }

    pub fn get_hash_hex(&self) -> String {
        hex::encode(calculate_hash(
            if self.verify {
                &self.secret[0..self.secret.len() - 64]
            }
            else {
                &self.secret
            }))
    }
            


    /// Performs the reconstruction of the shares. No validation is done at the moment to verify
    /// that the reconstructed secret is correct.
    pub fn reconstructor(dir: &str, stem: &str, shares_required: usize, 
                         prime_location: PrimeLocation, verify: bool) -> Result<Self, Box<dyn Error>> {
        let share_paths = generate_share_file_paths(dir, stem, shares_required);
        
        let prime = match prime_location {
            PrimeLocation::Default => Prime::Default(DEFAULT_PRIME.clone()),
            PrimeLocation::InFile => {
                let prime_path = generate_prime_file_path(dir, stem);
                let bytes = std::fs::read(prime_path)?;
                Prime::NonDefault(BigInt::from_signed_bytes_be(bytes.as_slice()))
            }
        };

        let mut share_lists: Vec<Vec<BigInt>> = Vec::with_capacity(shares_required);
        for share_file_index in 0..shares_required {
            let mut buf_8: [u8; 8] = [0; 8];
            let mut share_file = File::open(&share_paths[share_file_index])?;
            share_file.read_exact(&mut buf_8)?;
            let num_shares = u64::from_be_bytes(buf_8);
            let mut share_list: Vec<BigInt> = Vec::with_capacity(num_shares as usize); 
            
            for _ in 0..num_shares {
                let mut buf_4: [u8; 4] = [0; 4];
                (&mut share_file).read_exact(&mut buf_4)?;
                let bytes_for_next_share = u32::from_be_bytes(buf_4);
                let mut share_bytes: Vec<u8> = Vec::with_capacity(bytes_for_next_share as usize);

                // 'take' the next 'bytes_for_next_share' bytes and read them all into the
                // 'share_bytes'
                (&mut share_file).take(bytes_for_next_share as u64).read_to_end(&mut share_bytes)?;

                let share = BigInt::from_signed_bytes_be(share_bytes.as_slice());
                share_list.push(share);
            }

            share_lists.push(share_list);

        }

        // They should have x-values in the order of 1,2,3... etc. 
        // These need to be re-added for the reconstruction function
        // The +1 for x_value is needed because enumerate generates indices from 0..<len of iteration>
        // but our coefficients start at 1.
        let mut x_val_counter = 0;
        let share_lists: Vec<Vec<Point>> = share_lists
                         .into_iter()
                         .map(|share_list| {
                            *(&mut x_val_counter) = *(&x_val_counter) + 1;
                            share_list.into_iter()
                                .map(|y_val| {
                                    Point::new(*(&x_val_counter), y_val)
                                }).collect()
                         }).collect();
       
        let recon_secret = reconstruct_secrets_from_share_lists(share_lists.clone(),
                                                                &*prime,
                                                                shares_required)?;

        if verify {
            let hash = &recon_secret[(recon_secret.len() - 64)..];
            let hasher_output = calculate_hash(&recon_secret.as_slice()[0..(recon_secret.len() - 64)]);

            if &hash != &hasher_output.as_slice() {
                let orig_hash = hex::encode(hash);
                let curr_hash = hex::encode(hasher_output);
                return Err(Box::new(SharerError::VerificationFailure(orig_hash, curr_hash)));
            }



        }

        Ok(Sharer {
            share_lists: share_lists,
            secret: recon_secret,
            prime: prime,
            shares_required: shares_required,
            verify: verify
        })



    }

}


impl SharerBuilder {
    
    /// Builds the Sharer and constructs the shares.
    pub fn build(mut self) -> Result<Sharer, Box<dyn Error>> {

        if self.secret.len() == 0 {
            return Err(Box::new(SharerError::EmptySecret));
        }
        if self.shares_required < 2 || self.shares_to_create < 2 {
            return Err(Box::new(SharerError::InvalidNumberOfShares(self.shares_required)));
        }

        // Check for the verify flag and if it is true append a hash
        if self.verify {
            let hasher_output = calculate_hash(&self.secret.as_slice());
            self.secret.extend_from_slice(&hasher_output);
        }            
        
        let share_lists = create_share_lists_from_secrets(   self.secret.as_slice(),
                                                        self.prime.deref(),
                                                        self.shares_required,
                                                        self.shares_to_create,
                                                        self.coefficient_bits)?;

            Ok(Sharer {
            share_lists: share_lists,
            secret: self.secret,
            prime: self.prime,
            shares_required: self.shares_required,
            verify: self.verify,
        })

    }

    /// Use a specific prime for the generation of the shares. The given prime is checked with an
    /// astronomically low chance for being incorrect. It's recommended to use the default prime or
    /// randomly generate one with rand_prime
    pub fn prime(mut self, prime: BigUint) -> Result<Self, SharerError> {
        if num_bigint_dig::prime::probably_prime(&prime, 25) {
            self.prime = Prime::NonDefault(prime.into());
            Ok(self)
        }
        else {
            Err(SharerError::NotPrime(prime))
        }
    }


    /// Uses the given RNG to seed the RNG that generates the prime number. The prime number will
    /// be generated with prime_bits number of bits. If None is specified for the RNG, then StdRng
    /// is used and seeded from entropy.
    pub fn rand_prime<T: Rng>(mut self, rng: Option<T>, prime_bits: usize) -> Self {
        self.prime = match rng {
            Some(mut rng) => Prime::NonDefault(rng.gen_prime(prime_bits).into()),
            None => Prime::NonDefault(StdRng::from_entropy().gen_prime(prime_bits).into()),
        };
        self
    }

    pub fn coefficient_bits(mut self, coefficient_bits: usize) -> Self {
        self.coefficient_bits = coefficient_bits;
        self
    }

    pub fn shares_required(mut self, shares_required: usize) -> Self {
        self.shares_required = shares_required;
        if self.shares_required < self.shares_to_create {
            self.shares_to_create = shares_required;
        }
        self
    }

    pub fn shares_to_create(mut self, shares_to_create: usize) -> Self {
        self.shares_to_create = shares_to_create;
        if self.shares_to_create < self.shares_required {
            self.shares_required = self.shares_to_create;
        }
        self
    }

    pub fn verify(mut self, verify: bool) -> Self {
        self.verify = verify;
        self
    }

    pub fn secret(mut self, secret: Vec<u8>) -> Self {
        self.secret = secret;
        self
    }

}


impl Default for SharerBuilder {
    fn default() -> Self {
        Self {
            secret: Vec::with_capacity(0),
            coefficient_bits: 32,
            shares_required: 3,
            shares_to_create: 3,
            prime: Prime::Default(DEFAULT_PRIME.clone()),
            verify: true,
        }

    }

}


#[derive(Debug, Clone)]
pub enum SharerError {
    NotPrime(BigUint),
    ReconstructionNotEqual,
    EmptySecret,
    InvalidNumberOfShares(usize),
    VerificationFailure(String, String),
}

impl std::fmt::Display for SharerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SharerError::NotPrime(not_prime) => {
                write!(f, "{} is not a prime number, which is required for SSS", not_prime)
            },
            SharerError::ReconstructionNotEqual => {
                write!(f, "Reconstructed secret is not equivalent to initial secret")
            },
            SharerError::EmptySecret => {
                write!(f, "Cannot share an empty secret. Secret cannot have a length of 0")
            },
            SharerError::InvalidNumberOfShares(given) => {
                write!(f, "Must create at least 2 shares for sharing. Given: {}", given)
            },
            SharerError::VerificationFailure(original_hash, calculated_hash) => {
                write!(f, 
"Verification of reconstructed secret failed. Mismatched hashes:
Original Hash: {}
Calculated Hash: {}",
                      original_hash,
                      calculated_hash)
            },

        }
    }
}

impl Error for SharerError {}







// Generates paths for the shares with in given dir with a given stem. 
// It is assumed that dir is a valid directory, no checks are done.
fn generate_share_file_paths(dir: &str, stem: &str, num_files: usize) -> Vec<String> {
    let mut path_buf = Path::new(dir).to_path_buf();
    let mut generated_paths: Vec<String> = Vec::with_capacity(num_files);

    for i in 0..num_files {
        path_buf.push(format!("{}.s{}", stem, i));
        (&mut generated_paths).push(String::from(path_buf.to_str().unwrap()));
        path_buf.pop();
    }

    generated_paths
}

// Generates the path for the prime file with the given dir and file path
fn generate_prime_file_path(dir: &str, prime_file: &str) -> String {
    let mut path_buf = Path::new(dir).to_path_buf();
    path_buf.push(prime_file);
    format!("{}.prime", path_buf.to_str().unwrap())
}



fn calculate_hash(secret: &[u8]) -> Vec<u8> {
    let hash_input_num_bytes = if secret.len() < NUM_FIRST_BYTES_FOR_VERIFY {
        secret.len()
    }
    else {
        NUM_FIRST_BYTES_FOR_VERIFY
    };

    let mut hasher_output = [0u8; 64];
    let mut hasher = Sha3::sha3_512();
    hasher.input(&secret[0..hash_input_num_bytes]);
    hasher.result(&mut hasher_output);
    hasher_output.to_vec()
}





#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn basic_share_reconstruction() {
        let dir = "./";
        let stem = "basic_share_reconstruction_test";
        let num_shares = 3;
        let secret: Vec<u8> = vec![5, 4, 9, 1, 2, 128, 43];
        let sharer = Sharer::builder(secret)
            .shares_required(num_shares)
            .shares_to_create(num_shares)
            .coefficient_bits(32)
            .verify(true)
            .build()
            .unwrap();
        sharer.share_to_files(dir, stem).unwrap();
       
        let recon = match Sharer::reconstructor(dir, stem, num_shares, PrimeLocation::Default, true) {
            Ok(secret) => secret,
            Err(e) => {
                println!("Couldn't recontruct shares: {}", e);
                panic!("Couldn't reconstruct shares: {}", e);
            }
        };

        // Cleanup
        for path in generate_share_file_paths(dir, stem, num_shares) {
            match std::fs::remove_file(&path) {
                Ok(_) => (),
                Err(e) => {
                    println!("Couldn't cleanup file '{}': {}", &path, e);
                }
            }
        }
        
        assert_eq!(*sharer.get_secret(), *recon.get_secret()); 
        sharer.test_reconstruction_file(None).expect("Reconstruction test failed");

    }



    #[test]
    fn zero_test() {
        let dir = "./";
        let stem = "zero_test";
        let num_shares = 3;
        let secret: Vec<u8> = vec![0];
        let sharer = Sharer::builder(secret)
            .shares_required(num_shares)
            .shares_to_create(num_shares)
            .coefficient_bits(32)
            .build()
            .unwrap();
        sharer.share_to_files(dir, stem).unwrap();
        let recon = Sharer::reconstructor(dir, stem, num_shares, PrimeLocation::Default, true).unwrap();
        for path in generate_share_file_paths(dir, stem, num_shares) {
            match std::fs::remove_file(&path) {
                Ok(_) => (),
                Err(e) => {
                    println!("Couldn't cleanup file '{}': {}", &path, e);
                }
            }
        }
        assert_eq!(sharer.get_secret(), recon.get_secret());

    }

    #[test]
    #[should_panic]
    fn fail_verify() {
        let dir = "./";
        let stem = "fail_verify";
        let secret = vec![1,2,3,4,5];
        let sharer = Sharer::builder(secret).build().unwrap();
        sharer.share_to_files(dir, stem).unwrap();
        
        let mut bytes = std::fs::read("./fail_verify.s0").unwrap();
        bytes[12] = bytes[12] ^ 255u8;
        std::fs::write("./fail_verify.s0", bytes).unwrap();
        let recon = Sharer::reconstructor(dir, stem, 3, PrimeLocation::Default, true).unwrap(); 
       
    } 




}







