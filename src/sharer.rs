use crate::raw_share::*;
use crate::geometry::Point;
use rand::{Rng, FromEntropy};
use rand::rngs::StdRng;
use std::io::{Read, Write, Seek, SeekFrom};
use std::error::Error;
use std::fs::File;
use std::path::Path;
use std::ops::Deref;
use crypto::sha3::Sha3;
use crypto::digest::Digest;
use std::convert::TryInto;


const NUM_FIRST_BYTES_FOR_VERIFY: usize = 32;
const READ_SEGMENT_SIZE: usize = 512_000; // 512 KB



/// Defines a prime as either THE default prime, or a NonDefault one either generated or given
/// statically. If the default one is used it doesn't make sense to write it to a file
#[derive(Debug, Clone)]
enum Prime {
    Default(i64),
    NonDefault(i64),
}

/// Contains the secret, whether in file or in memory stored in Vec of bytes
#[derive(Debug)]
pub enum Secret {
    InMemory(Vec<u8>),
    InFile(String),
}

// Rust thinks it's dead code because a ptr is pulled from it and then it's set but never accessed,
// but the ptr is used to reconstruct a slice that is used as the reader.
#[allow(dead_code)]
pub struct SecretIterator {
    secret: Option<Vec<u8>>, // If the secret is InMemory, this will be some vector
    reader: Box<dyn Read>, // reader is a reader of the vec in secret, or it's to an open file
}

/// Defines the location of the prime to the reconstruct_from_files, if it's the default prime, or if it was
/// saved to a file. InFile doesn't have any data since the file should always be the stem appended
/// with '.prime'
#[derive(Debug, Clone)]
pub enum PrimeLocation {
    InFile, // The prime file is location in a file and is not the default 
    Default, // The prime isn't in any file, the default prime was used.
}

impl Deref for Prime {
    type Target = i64;
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
    secret: Secret,
    prime: Prime,
    shares_required: usize,
    shares_to_create: usize,
}

/// The builder struct to give the Sharer struct  builder style construction. 
/// Defaults:
///     - prime: Prime::Default(<The default prime>)
///     - shares_required: 3
///     - shares_to_create: 3
#[derive(Debug)]
pub struct SharerBuilder {
    secret: Secret, // The secret to be shared 
    prime: Prime, // The prime number use to bring the underlying share polynomial into a finite field
    shares_required: usize, // The number of shares needed to reconstruct the secret
    shares_to_create: usize, // The number of shares to generate
}



impl Sharer {

    /// Constructs the builder with defualt values. See the builder documentation for the default
    /// values.
    pub fn builder(secret: Secret) -> SharerBuilder {
        SharerBuilder { secret: secret, 
                        ..Default::default()
        }
    }

    /// Shares all the shares to individual writeable destinations. This iterates through the
    /// secret and calculates the share lists in chunks and writes the shares to their respective
    /// destinations
    pub fn share(&self, mut dests: Vec<Box<dyn Write>>) 
        -> Result<(), Box<dyn Error>> {

            
        if dests.len() < self.shares_to_create {
            return Err(Box::new(
                    SharerError::NotEnoughWriteableDestinations(dests.len(), self.shares_to_create)));
        }
        
        for secret_segment in (&self.secret).into_iter() {
           
            // Return error if seret_segment is an error, or unwrap it if its ok
            let secret_segment = secret_segment?; 

            let share_lists = create_share_lists_from_secrets(secret_segment.as_slice(),
                                                         *self.prime.deref(),
                                                         self.shares_required,
                                                         self.shares_to_create)?;
            // shares is now the first N points of the entire share, iterate through the
            // share_lists and the destinations and write each share_list into each destination.
            // Each share_list contains a point, which is mapped to just the y value's numerator
            // in bytes, since we do not need the x value to be written out
            for (share_list, dest) in (&share_lists).into_iter().zip((&mut dests).into_iter()) {
                // This iterater mess below just maps each point in the current share list to just
                // its y-value in bytes, then flattens all those bytes together into a single slice
                // that is written to the dest
                // TODO: Use a dedicated function to do the below processing of the share list
                dest.write_all(
                            share_list.into_iter()
                                       .map(|point| point.y().get_numerator().to_be_bytes().to_vec())
                                       .flatten()
                                       .collect::<Vec<u8>>()
                                       .as_slice()
                              )?;
            }

                                                            
        }

        // Now that all of the shares have been written to, calculate the hash and share the hash
        // to the destinations
        let hash = self.secret.calculate_hash()?;
        for dest in &mut dests {
            dest.write_all(hash.as_slice())?;
        }
        Ok(())
    }

    /// Outputs the prime to a given writeable destination.
    pub fn share_prime<T: Write>(&self, dest: &mut T) -> Result<(), Box<dyn Error>> {
        dest.write_all(&self.prime.to_be_bytes())?;
        Ok(())
    }



    /// Shares all the shares to separate files for distribution. 
    /// @stem: Defines the stem of the output files, they will be @stem.s0, @stem.s1, and so on..
    /// @dir: The directory to output the shares to.
    ///
    /// If @dir isn't valid, the LAST invalid destination file's error is returned. 
    pub fn share_to_files(&self, dir: &str, stem: &str) -> Result<(), Box<dyn Error>> {
        let file_paths = generate_share_file_paths(dir, stem, self.shares_to_create);

        let mut dests: Vec<Box<dyn Write>> = Vec::with_capacity(self.shares_to_create);

        for path in file_paths {
            let f = File::open(path)?;
            dests.push(Box::new(f) as Box<dyn Write>);
        }

        self.share(dests)?;

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
        // TODO: This is the last function that needs a rewrite, then testing can begin.    
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

        
        Ok(())

    }

    pub fn get_hash_hex(&self) -> Result<String, Box<dyn Error>> {
        Ok(hex::encode(self.secret.calculate_hash()?))
    }

    /// Reconstructs a Sharer from a given list of srcs. The srcs should all read the same number
    /// of bytes. 
    pub fn reconstruct_from_srcs(mut srcs: Vec<Box<dyn Read>>, prime: Option<Box<dyn Read>>, 
                                 mut secret_type: Secret) -> Result<Self, Box<dyn Error>> {

        let prime = match prime {
            Some(mut reader) => {
                let mut buf = [0u8; 8];
                reader.read_exact(&mut buf)?;
                i64::from_be_bytes(buf)
            },
            None => DEFAULT_PRIME,
        };

        let mut dest: Box<dyn Write> = match secret_type {
            Secret::InMemory(ref mut vec) => Box::new(vec) as Box<dyn Write>,
            Secret::InFile(ref path) => Box::new(File::create(path)?) as Box<dyn Write>,
        };

        'outer: loop {
            let mut segments: Vec<Vec<Point>> = Vec::with_capacity(srcs.len());

            // Read in one segment size from each share
            for src in &mut srcs {
                let mut buf: Vec<u8> = Vec::with_capacity(READ_SEGMENT_SIZE);
                src.take(READ_SEGMENT_SIZE as u64).read_to_end(&mut buf)?;
                if buf.len() == 0 {
                    // The srcs are now empty, break
                    // Have to return something for some reason, so return garbage.
                    // TODO: Find a way to avoid this. No other breaks in this loop, so is this
                    // required return value coming from the ? operator? Does that mean these
                    // errors aren't getting returned from this function?
                    break 'outer Err(Box::new(SharerError::EmptySecret));
                }
                
                // Seperate the vec into chunks an convert those chunks to i64 and map them to
                // points
                let mut map_ret_val: Result<(), Box<dyn Error>> = Ok(());
                let conv_to_points: Vec<Point> = 
                    buf.as_slice()
                        .chunks(std::mem::size_of::<i64>())
                        .enumerate()
                        .map(|(i, chunk)| {
                            if chunk.len() < std::mem::size_of::<i64>() {
                                // An invalid number of trailing bytes was at the end of the src
                                // Return a dummpy point and set the map_ret_val
                                map_ret_val = 
                                    Err(Box::new(SharerError::InvalidNumberOfBytesFromSource(chunk.len())));
                                Default::default()
                            }
                            else {
                                let (i64_bytes, _) = chunk.split_at(std::mem::size_of::<i64>());
                                Point::new((i + 1) as i64, i64::from_be_bytes(i64_bytes.try_into().unwrap()))
                            }
                        })
                        .collect();

                if let Err(e) = map_ret_val {
                    // Could not map all bytes from a src to i64
                    return Err(e);
                }

                segments.push(conv_to_points);
                                                    

            }
            
            // Now segments has a segment from each share src, reconstruct the secret up to that
            // point and write it to the destination
            dest.write_all(reconstruct_secrets_from_share_lists(segments, prime, srcs.len())?.as_slice())?;

        }


    }


            


    /// Performs the reconstruction of the shares. No validation is done at the moment to verify
    /// that the reconstructed secret is correct.
    pub fn reconstruct_from_files(dir: &str, stem: &str, shares_required: usize, 
                         prime_location: PrimeLocation) -> Result<Self, Box<dyn Error>> {

        let share_paths = generate_share_file_paths(dir, stem, shares_required);
        let share_files: Vec<Result<File, Box<dyn Error>>> = share_paths.into_iter()
                                                           .map(|path| File::open(path)
                                                                .map_err(|e| Box::new(e) as Box<dyn Error>))
                                                           .collect();
        
       
        // Check that all the share files opened properly
        let mut unwrapped_share_files: Vec<File> = Vec::with_capacity(share_files.len());
        for file in share_files {
            unwrapped_share_files.push(file?);
        }


        // Now map the files to a dyn Read, which needed to wait till we got the len since Read
        // doesn't have a len method.
        let share_files: Vec<Box<dyn Read>> = unwrapped_share_files.into_iter()
                                                         .map(|file| Box::new(file) as Box<dyn Read>)
                                                         .collect();


        let prime: Option<Box<dyn Read>> = match prime_location {
            PrimeLocation::InFile => 
                Some(Box::new(File::open(generate_prime_file_path(dir, stem))?) as Box<dyn Read>),
            PrimeLocation::Default => None,
        };
        
        let mut secret_path = Path::new(dir).to_path_buf();
        secret_path.push(stem);
        let secret = Secret::InFile(String::from(secret_path.to_str().unwrap()));

        Self::reconstruct_from_srcs(share_files, prime, secret)

    }


}


impl SharerBuilder {
    
    /// Builds the Sharer and constructs the shares.
    pub fn build(self) -> Result<Sharer, Box<dyn Error>> {

        if self.secret.len()? == 0 {
            return Err(Box::new(SharerError::EmptySecret));
        }
        if self.shares_required < 2 || self.shares_to_create < 2 {
            return Err(Box::new(SharerError::InvalidNumberOfShares(self.shares_required)));
        }


        

        Ok(Sharer {
        secret: self.secret,
        prime: self.prime,
        shares_required: self.shares_required,
        shares_to_create: self.shares_to_create})


    }

    /// Use a specific prime for the generation of the shares. The given prime is checked with an
    /// astronomically low chance for being incorrect. It's recommended to use the default prime or
    /// randomly generate one with rand_prime
    pub fn prime(mut self, prime: i64) -> Result<Self, SharerError> {
        if primal_check::miller_rabin(prime as u64) {
            self.prime = Prime::NonDefault(prime);
            Ok(self)
        }
        else {
            Err(SharerError::NotPrime(prime))
        }
    }


    /// Uses the given RNG to seed the RNG that generates the prime number. The prime number will
    /// be generated with prime_bits number of bits. If None is specified for the RNG, then StdRng
    /// is used and seeded from entropy.
    pub fn rand_prime<T: Rng>(mut self, rng: Option<T>) -> Self {
        self.prime = match rng {
            Some(mut rng) => Prime::NonDefault(Self::gen_random_prime(&mut rng)),
            None => Prime::NonDefault(Self::gen_random_prime(&mut StdRng::from_entropy())),
        };
        self
    }

    fn gen_random_prime<T: Rng>(rng: &mut T) -> i64 {
        let mut maybe_prime: i64 = rng.gen_range(std::i16::MAX as i32, std::i32::MAX as i32) as i64;
        maybe_prime = maybe_prime | 1; // Ensure the number is odd
        while !primal_check::miller_rabin(maybe_prime as u64) {
            // Not prime, step down by 2
            maybe_prime = maybe_prime - 2;
        }

        maybe_prime
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


}


impl Default for SharerBuilder {
    fn default() -> Self {
        Self {
            secret: Secret::InMemory(Vec::with_capacity(0)),
            shares_required: 3,
            shares_to_create: 3,
            prime: Prime::Default(DEFAULT_PRIME),
        }

    }

}


impl std::iter::IntoIterator for &Secret {
    type Item = Result<Vec<u8>, Box<dyn Error>>;
    type IntoIter = SecretIterator;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Secret::InFile(ref path) => 
                SecretIterator { 
                    secret: None, 
                    reader: Box::new(File::open(path).unwrap()) as Box<dyn Read>
            },
            Secret::InMemory(ref boxed_slice) => {
                let secret_ptr = boxed_slice.as_ptr();
                let len = boxed_slice.len();
                unsafe {
                    // Since the boxed_slice that the reference in reader points to is part of the
                    // same object, the slice should always be valid
                    SecretIterator {
                        secret: Some(boxed_slice.to_vec()),
                        reader: Box::new(std::slice::from_raw_parts(secret_ptr, len)) as Box<dyn Read>
                    }
                }
            }
        }
    }
}


impl std::iter::Iterator for SecretIterator {
    type Item = Result<Vec<u8>, Box<dyn Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes_to_read = std::mem::size_of::<u8>() * READ_SEGMENT_SIZE;
        let mut result = Vec::with_capacity(bytes_to_read);
        if let Err(e) = (&mut self.reader).take(bytes_to_read as u64).read_to_end(&mut result) {
            // Return the error if an error ocurred during reading the next segment
            return Some(Err(Box::new(e) as Box<dyn Error>));
        }
        
        if result.len() == 0 {
            return None;
        }
        Some(Ok(result))
    }

}


impl Secret {

    pub fn len(&self) -> Result<u64, Box<dyn Error>> {
        match self {
            Secret::InFile(ref path) => Ok(std::fs::metadata(path)?.len()),
            Secret::InMemory(vec) => Ok(vec.len() as u64),
        }
    }

    pub fn calculate_hash(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut hasher_output = [0u8; 64];
        let mut hasher = Sha3::sha3_512();
        let hash_input_num_bytes = if self.len()? < NUM_FIRST_BYTES_FOR_VERIFY as u64 {
            self.len()? as usize 
        }
        else {
            NUM_FIRST_BYTES_FOR_VERIFY
        };

        let mut input_vec = Vec::with_capacity(hash_input_num_bytes);

        match self {
            Secret::InFile(ref path) => {
                let f = File::open(path)?;
                f.take(hash_input_num_bytes as u64).read_to_end(&mut input_vec)?;
            },
            Secret::InMemory(ref secret) => {
                input_vec.extend_from_slice(secret.as_slice());   
            },
        }

        hasher.input(input_vec.as_slice());
        hasher.result(&mut hasher_output);
        Ok(hasher_output.to_vec())

    }

    pub fn get_hash_from_end(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        match self {
            Secret::InFile(path) => {
                let mut hash = [0u8; 64];
                let mut f = File::open(path)?;
                f.seek(SeekFrom::End(-64))?;
                f.read_exact(&mut hash)?;
                Ok(hash.to_vec())
            },
            Secret::InMemory(vec) => {
                Ok(vec.as_slice()[(vec.len() - 64)..].to_vec())
            }
        }
    }




}

        






#[derive(Debug, Clone)]
pub enum SharerError {
    NotPrime(i64),
    ReconstructionNotEqual,
    EmptySecret,
    InvalidNumberOfShares(usize),
    NotEnoughWriteableDestinations(usize, usize),
    InvalidNumberOfBytesFromSource(usize),
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
            SharerError::NotEnoughWriteableDestinations(given, needed) => {
                write!(f, "Need {} writeable destinations for shares, only given {}", needed, given)
            },
            SharerError::InvalidNumberOfBytesFromSource(bytes) => {
                write!(f, "Excess trailing bytes, must be divisible by {}. Trailing: {}", 8, bytes)
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
            .build()
            .unwrap();
        sharer.share_to_files(dir, stem).unwrap();
       
        let recon = match Sharer::reconstruct_from_files(dir, stem, num_shares, PrimeLocation::Default, true) {
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
            .build()
            .unwrap();
        sharer.share_to_files(dir, stem).unwrap();
        let recon = Sharer::reconstruct_from_files(dir, stem, num_shares, PrimeLocation::Default, true).unwrap();
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
        let _recon = Sharer::reconstruct_from_files(dir, stem, 3, PrimeLocation::Default, true).unwrap(); 
       
    } 




}







