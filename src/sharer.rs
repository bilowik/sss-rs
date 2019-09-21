use crate::raw_share::*;
use crate::geometry::Point;
use rand::{Rng, FromEntropy};
use rand::rngs::StdRng;
use num_bigint_dig::{BigInt, BigUint, RandPrime};
use std::rc::Rc;
use std::io::{Read, Write};
use std::error::Error;
use std::fs::File;
use std::path::Path;
use std::ops::Deref;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref DEFAULT_PRIME: BigInt = BigInt::from(4173179203 as u32);
}



/// Defines a prime as either THE default prime, or a NonDefault one either generated or given
/// statically. If the default one is used it doesn't make sense to write it to a file
#[derive(Debug, Clone)]
enum Prime {
    Default(BigInt),
    NonDefault(BigInt),
}

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

#[derive(Debug)]
pub struct Sharer {
    share_lists: Vec<Vec<Point>>,
    secret: Rc<Vec<u8>>,
    prime: Prime,
    shares_required: usize,
}

#[derive(Debug)]
pub struct SharerBuilder {
    secret: Rc<Vec<u8>>, // The secret to be shared (Wrapped in an Rc to avoid having to make expensive
                         // copies)
    prime: Prime, // The prime number use to bring the underlying share polynomial into a finite field
    shares_required: usize, // The number of shares needed to reconstruct the secret
    shares_to_create: usize, // The number of shares to generate
    coefficient_bits: usize, // The number of bits the random coefficients of the polynomial will have.
}



impl Sharer {

    pub fn builder(secret: Vec<u8>) -> SharerBuilder {
        SharerBuilder { secret: Rc::new(secret), 
                        ..Default::default()
        }
    }

    /// Shares a single share, designated by share_num, to a writable destination.
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

        let recon = Sharer::reconstructor(dir, stem, self.shares_required, prime_location.clone())?;
        
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

    pub fn get_secret(&self) -> Rc<Vec<u8>> {
        self.secret.clone()
    }


    pub fn reconstructor(dir: &str, stem: &str, shares_required: usize, 
                         prime_location: PrimeLocation) -> Result<Self, Box<dyn Error>> {
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
            // TODO: Ensure support for secrets greater than 4GB, a custom Vec-like data type that
            // can accept u128 indices by appending extra vectors would work. This needs to be impl
            // at the library level as well however.
            // Having 4 GB of data in a vec is not exactly a great practice so possibly a better
            // alternative is some sort of buffered reading and use of the data. 
            // IE: Loop through the first 1 GB / shares_needed and calculate the secret up to that
            // point. This would however, make the shuffle operation impossible unless done
            // in-file.
            // TODO: Move this information into the todo file
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

        Ok(Sharer {
            share_lists: share_lists,
            secret: Rc::new(recon_secret),
            prime: prime,
            shares_required: shares_required,
        })



    }

}


impl SharerBuilder {
    pub fn build(self) -> Result<Sharer, Box<dyn Error>> {
        if self.secret.len() == 0 {
            return Err(Box::new(SharerError::EmptySecret));
        }
        if self.shares_required < 2 || self.shares_to_create < 2 {
            return Err(Box::new(SharerError::InvalidNumberOfShares(self.shares_required)));
        }
        
        let share_lists = create_share_lists_from_secrets(   self.secret.as_slice(),
                                                        self.prime.deref(),
                                                        self.shares_required,
                                                        self.shares_to_create,
                                                        self.coefficient_bits)?;

        Ok(Sharer {
            share_lists: share_lists,
            secret: self.secret.clone(),
            prime: self.prime.clone(),
            shares_required: self.shares_required,
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

    pub fn secret(mut self, secret: Vec<u8>) -> Self {
        self.secret = Rc::new(secret);
        self
    }

}


impl Default for SharerBuilder {
    fn default() -> Self {
        Self {
            secret: Rc::new(Vec::with_capacity(0)),
            coefficient_bits: 32,
            shares_required: 3,
            shares_to_create: 3,
            prime: Prime::Default(DEFAULT_PRIME.clone())
        }

    }

}



#[derive(Debug, Clone)]
pub enum SharerError {
    NotPrime(BigUint),
    ReconstructionNotEqual,
    EmptySecret,
    InvalidNumberOfShares(usize),
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
            }

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





#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn basic_share_reconstruction() {
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

        // Cleanup
        for path in generate_share_file_paths(dir, stem, num_shares) {
            std::fs::remove_file(path).unwrap();
        }
        
        assert_eq!(*sharer.get_secret(), *recon.get_secret()); 
        sharer.test_reconstruction_file(None).expect("Reconstruction test failed");

    }



    #[test]
    fn zero_test() {
        let dir = "./";
        let stem = "test";
        let num_shares = 3;
        let secret: Vec<u8> = vec![0];
        let sharer = Sharer::builder(secret)
            .shares_required(num_shares)
            .shares_to_create(num_shares)
            .coefficient_bits(32)
            .build()
            .unwrap();
        sharer.share_to_files(dir, stem).unwrap();
        let recon = Sharer::reconstructor(dir, stem, num_shares, PrimeLocation::Default).unwrap();

        for path in generate_share_file_paths(dir, stem, num_shares) {
            std::fs::remove_file(path).unwrap();
        }
        assert_eq!(*sharer.get_secret(), *recon.get_secret());

    }


}







