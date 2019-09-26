use crate::raw_share::*;
use crate::geometry::Point;
use rand::{Rng, FromEntropy};
use rand::rngs::StdRng;
use std::io::{Read, Write};
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
       
        // This converts a point list to its raw bytes of its y-values flattened into a single vec
        // This is here as a closure since its used at two different points in this function
        let point_list_to_bytes = |vec: Vec<Point>| -> Vec<u8> {
            vec.into_iter()
               .map(|point| point.y().get_numerator().to_be_bytes().to_vec())
               .flatten()
               .collect::<Vec<u8>>()
        };

        // This just writes each corresponding share_list in share_lists to a dest in dests. This
        // is written here as a closure since it's used at two different points in this function
        let share_lists_to_dests = |lists: Vec<Vec<Point>>, mut dests: &mut Vec<Box<dyn Write>>| 
                -> Result<(), Box<dyn Error>> {
            for (share_list, dest) in lists.into_iter().zip((&mut dests).into_iter()) {
                dest.write_all(point_list_to_bytes(share_list).as_slice())?;
            }
            Ok(())
        };
              


            
        if dests.len() < self.shares_to_create {
            // Not enough dests to share shares to
            return Err(Box::new(
                    SharerError::NotEnoughWriteableDestinations(dests.len(), self.shares_to_create)));
        }
        
        for secret_segment in (&self.secret).into_iter() {

            // Return error if seret_segment is an error, or unwrap it if its ok. This can happen
            // if the secret is a file and a reading error occured during iteration
            let secret_segment = secret_segment?; 

            let share_lists = create_share_lists_from_secrets(secret_segment.as_slice(),
                                                         *self.prime.deref(),
                                                         self.shares_required,
                                                         self.shares_to_create)?;
            dbg!(&share_lists);
            share_lists_to_dests(share_lists, &mut dests)?;
                                                            
        }

        // Now that all of the shares have been written to, calculate the hash and share the hash
        // to the dests
        let hash = self.secret.calculate_hash()?;
        let share_lists = create_share_lists_from_secrets(&hash,
                                                           *self.prime.deref(),
                                                           self.shares_required,
                                                           self.shares_to_create)?;

        // The shares for the hash have been created, write them all to dests
        share_lists_to_dests(share_lists, &mut dests)?;
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
            let f = File::create(path)?;
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
        let default_dir = "./";
        let dir = match dir {
            Some(dir_str) => dir_str,
            None => default_dir,
        };
        let stem = ".tmp_share_file";

        let prime_location = match self.prime {
            Prime::NonDefault(_) => PrimeLocation::InFile,
            Prime::Default(_) => PrimeLocation::Default,
        };
   
        let mut recon_secret = Secret::point_at_file(".tmp_secret_recon");

        self.share_to_files(dir, stem)?;
        recon_secret.reconstruct_from_files(dir, stem, self.shares_required, prime_location)?;

        // Cleanup
        for path in generate_share_file_paths(dir, stem, self.shares_required) {
            std::fs::remove_file(path).ok();
        }
        std::fs::remove_file(generate_prime_file_path(dir, stem)).ok();

        
        Ok(())

    }

    pub fn get_hash_hex(&self) -> Result<String, Box<dyn Error>> {
        Ok(hex::encode(self.secret.calculate_hash()?))
    }



            



    pub fn get_secret<'a>(&'a self) -> &'a Secret {
        &self.secret
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

    pub fn empty_in_memory() -> Self {
        Secret::InMemory(Vec::new())
    }
    pub fn empty_in_memory_with_capacity(capacity: usize) -> Self {
        Secret::InMemory(Vec::with_capacity(capacity))
    }
    pub fn point_at_file(path: &str) -> Self {
        Secret::InFile(String::from(path))
    }

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

    /// Calculates a hash and compares it to the given hash. Returns Ok(true) if they're
    /// equivalent, Ok(false) if they aren't or an error if there was an issue calculating the hash
    /// (likely a read error if Secret was a file)
    pub fn verify(&self, hash: &[u8]) -> Result<bool, Box<dyn Error>> {
        Ok(self.calculate_hash()? == hash.to_vec())
    }


    /// Reconstructs a secret from a given list of srcs. The srcs should all read the same number
    /// of bytes. 
    /// @src_len MUST be an accurate length of the shares read in from the srcs
    pub fn reconstruct_from_srcs(&mut self, mut srcs: Vec<Box<dyn Read>>, prime: Option<Box<dyn Read>>, 
                                 src_len: u64) -> Result<(), Box<dyn Error>> {
       
        // Closure that converts bytes to i64 points
        let to_i64_points = |vec: Vec<u8>, segment_num: i64| -> Result<Vec<Point>, Box<dyn Error>> {
            vec.as_slice()
                .chunks(std::mem::size_of::<i64>())
                .map(|chunk| {
                    if chunk.len() < std::mem::size_of::<i64>() {
                        // An invalid number of trailing bytes was at the end of the src
                        Err(Box::new(SharerError::InvalidNumberOfBytesFromSource(chunk.len())) as Box<dyn Error>)
                    }
                    else {
                        let (i64_bytes, _) = chunk.split_at(std::mem::size_of::<i64>());
                        Ok(Point::new(segment_num, i64::from_be_bytes(i64_bytes.try_into().unwrap())))
                    }
                })
                .collect()
        };



        let prime = match prime {
            Some(mut reader) => {
                let mut buf = [0u8; 8];
                reader.read_exact(&mut buf)?;
                Prime::NonDefault(i64::from_be_bytes(buf))
            },
            None => Prime::Default(DEFAULT_PRIME),
        };

        let mut dest: Box<dyn Write> = match self {
            Secret::InMemory(ref mut vec) => Box::new(vec) as Box<dyn Write>,
            Secret::InFile(ref path) => Box::new(File::create(path)?) as Box<dyn Write>,
        };

        let mut byte_counter = 0;
        while (byte_counter as i64) < ((src_len as i64) - (READ_SEGMENT_SIZE as i64)) {
            let mut segments: Vec<Vec<Point>> = Vec::with_capacity(srcs.len());

            // Read in one segment size from each share
            let mut segment_ctr = 1;
            for src in &mut srcs {
                let mut buf: Vec<u8> = Vec::with_capacity(READ_SEGMENT_SIZE);
                src.take(READ_SEGMENT_SIZE as u64).read_to_end(&mut buf)?;
                
                // Seperate the vec into chunks an convert those chunks to i64 and map them to
                // points
                let conv_to_points: Vec<Point> = to_i64_points(buf, segment_ctr)?;


                segments.push(conv_to_points);
                segment_ctr = segment_ctr + 1; // Keeps track of the x_values for each segment                  

            }

            // Now segments has a segment from each share src, reconstruct the secret up to that
            // point and write it to the destination
            dest.write_all(reconstruct_secrets_from_share_lists(segments, *prime, srcs.len())?.as_slice())?;

            byte_counter = byte_counter + READ_SEGMENT_SIZE as u64;

        }


        // We are now on the last segment which includes the hash at the end.
        // 
        let hash_bytes = 512;
        let remaining_secret_bytes: usize = (src_len - byte_counter - hash_bytes) as usize; 
        let mut segments: Vec<Vec<Point>> = Vec::with_capacity(srcs.len());
        let mut hash_segments: Vec<Vec<Point>> = Vec::with_capacity(srcs.len());

        let mut segment_ctr = 1;
        for src in &mut srcs {
            let mut buf: Vec<u8> = Vec::with_capacity(remaining_secret_bytes);
            let mut hash = [0u8; 512];
            src.take(remaining_secret_bytes as u64).read_to_end(&mut buf)?;
            src.read_exact(&mut hash)?; 
            segments.push(to_i64_points(buf.to_vec(), segment_ctr)?);
            hash_segments.push(to_i64_points(hash.to_vec(), segment_ctr)?);
            segment_ctr = segment_ctr + 1;
        }
        // Reconstruct the pointes from the bytes in the shares

        dbg!(&segments);
        
        dest.write_all(reconstruct_secrets_from_share_lists(segments, *prime, srcs.len())?.as_slice())?;
        let recon_hash = reconstruct_secrets_from_share_lists(hash_segments, *prime, srcs.len())?;

        // Drop dest since if it is a file, we will be re-opening it to read from it to
        // calculate the hash
        std::mem::drop(dest);
        if !self.verify(recon_hash.as_slice())? {
            let calc_hash_hex = hex::encode(&dbg!(self).calculate_hash()?);
            let orig_hash_hex = hex::encode(&recon_hash);
            return Err(Box::new(SharerError::VerificationFailure(orig_hash_hex, calc_hash_hex)));
        }

    
       Ok(()) // Which has now been filled with the original secret, either in a file via a path or
                       // a vec
    }

    /// Performs the reconstruction of the shares. No validation is done at the moment to verify
    /// that the reconstructed secret is correct.
    pub fn reconstruct_from_files(&mut self, dir: &str, stem: &str, shares_required: usize, 
                         prime_location: PrimeLocation) -> Result<(), Box<dyn Error>> {

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
        let len = unwrapped_share_files[0].metadata()?.len();


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

        self.reconstruct_from_srcs(share_files, prime, len)

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
        let num_shares = 2;
        let secret: Vec<u8> = vec![5, 4, 1, 8, 1, 2];
        let sharer = Sharer::builder(Secret::InMemory(secret))
            .shares_required(num_shares)
            .shares_to_create(num_shares)
            .build()
            .unwrap();
        sharer.share_to_files(dir, stem).unwrap();
        
        let mut recon = Secret::empty_in_memory();

         match recon.reconstruct_from_files(dir, stem, num_shares, PrimeLocation::Default) {
            Ok(_) => (),
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

        match (sharer.get_secret(), &recon) {
            (Secret::InMemory(orig_secret), Secret::InMemory(recon_secret)) => {
                assert_eq!(orig_secret, recon_secret);
            }
            _ => {
                panic!("Secrets are not both in memory?");
            }
        }

    }


    /*
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
    */



}







