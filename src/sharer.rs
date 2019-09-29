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
use std::convert::TryFrom;
use log::*;


const NUM_FIRST_BYTES_FOR_VERIFY: usize = 32;
const READ_SEGMENT_SIZE: usize = 8_192; // 8 KB, which has shown optimal perforamnce




/// Creates shares from a given secret. Shares to any suitable destination that implements Write
/// and has conveinence functions for files. To instantiate, the builder should be used.
#[derive(Debug)]
pub struct Sharer {
    secret: Secret, // The source of the secret, either an in memory vec or a file path
    prime: Prime, // The prime used for the secret sharing finite field arithmetic
    shares_required: usize, // The number of shares required to reconstruct the secret
    shares_to_create: usize, // The number of shares to create
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
    pub fn share(&self, mut dests: &mut Vec<Box<dyn Write>>) 
        -> Result<(), Box<dyn Error>> {

        // logging information
        let l = log_enabled!(Level::Info);
        let mut percent_finished: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut bytes_finished: u64 = 0;
        if l {
            total_bytes = self.secret.len()?;
            bytes_finished = 0;
        }


            
       
        // This converts a point list to its raw bytes of its y-values flattened into a single vec
        // This is here as a closure since its used at two different points in this function
        let point_list_to_bytes_u32 = |vec: Vec<Point>| -> Vec<u8> {
            vec.into_iter()
               .map(|point| (point.y().get_numerator() as u32).to_be_bytes().to_vec())
               .flatten()
               .collect::<Vec<u8>>()
        };
        let point_list_to_bytes_u8 = |vec: Vec<Point>| -> Vec<u8> {
            vec.into_iter()
               .map(|point| point.y().get_numerator() as u8)
               .collect::<Vec<u8>>()
        };

        // This just writes each corresponding share_list in share_lists to a dest in dests. This
        // is written here as a closure since it's used at two different points in this function
        let share_lists_to_dests = |lists: Vec<Vec<Point>>, mut dests: &mut Vec<Box<dyn Write>>, 
                                                point_list_to_bytes: &dyn Fn(Vec<Point>) -> Vec<u8>| 
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
            if l {
                info!("{}%: {} of {} shared", percent_finished, bytes_finished, total_bytes);
            }

            // Return error if seret_segment is an error, or unwrap it if its ok. This can happen
            // if the secret is a file and a reading error occured during iteration
            let secret_segment = secret_segment?; 
            let secret_segment_chunk_iter: std::slice::ChunksExact<'_,_>= secret_segment.as_slice()
                .chunks_exact(std::mem::size_of::<u32>());
            let remainder = secret_segment_chunk_iter.remainder();

            let secret_segment_u32: Vec<u32> = secret_segment_chunk_iter.map(|chunk| u32::from_be_bytes(
                        chunk.split_at(std::mem::size_of::<u32>()).0.try_into().unwrap()))
                .collect();

            if secret_segment_u32.len() > 0 {
                let share_lists = create_share_lists_from_secrets_u32(secret_segment_u32.as_slice(),
                                                             *self.prime.deref(),
                                                             self.shares_required,
                                                             self.shares_to_create)?;
                share_lists_to_dests(share_lists, &mut dests, &point_list_to_bytes_u32)?;
                if l {
                    bytes_finished = bytes_finished + (READ_SEGMENT_SIZE as u64);
                    percent_finished = (bytes_finished * 100) / total_bytes;
                }
            }

            // Now share the remainder (if any)
            if remainder.len() > 0 {
                let share_lists_remainder = create_share_lists_from_secrets(remainder,
                                                                            *self.prime,
                                                                            self.shares_required,
                                                                            self.shares_to_create)?;
                share_lists_to_dests(share_lists_remainder, &mut dests, &point_list_to_bytes_u8)?;
            }


            std::mem::drop(secret_segment); // ensure the memory DOES get dropped
        }

        // Now that all of the shares have been written to, calculate the hash and share the hash
        // to the dests
        let hash: Vec<u32> = u8_vec_to_u32(self.secret.calculate_hash()?.to_vec())?;
        let share_lists = create_share_lists_from_secrets_u32(&hash,
                                                           *self.prime.deref(),
                                                           self.shares_required,
                                                           self.shares_to_create)?;

        // The shares for the hash have been created, write them all to dests
        share_lists_to_dests(share_lists, dests, &point_list_to_bytes_u32)?;

        // Flush writes to all dests to ensure all bytes are written
        for dest in (&mut dests).into_iter() {
            dest.flush().ok();
        }
        Ok(())
    }

    /// Outputs the prime to a given writeable destination.
    pub fn share_prime<T: Write>(&self, dest: &mut T) -> Result<(), Box<dyn Error>> {
        dest.write_all(&self.prime.to_be_bytes())?;
        Ok(())
    }



    /// Shares all the shares to separate files for distribution. This also outputs the prime to a
    /// file as well if it isn't the default. This is a wrapper for the $share function.
    ///
    /// Format:
    ///     $dir/$stem.s<share_number>  For the shares
    ///     $dir/$stem.prime            For the prime, if it isn't the default. 
    ///
    /// $stem: Defines the stem of the output files, they will be $stem.s0, $stem.s1, and so on..
    /// $dir: The directory to output the shares to.
    ///
    /// If $dir isn't valid, the LAST invalid destination file's error is returned. 
    pub fn share_to_files(&self, dir: &str, stem: &str) -> Result<(), Box<dyn Error>> {
        let file_paths = generate_share_file_paths(dir, stem, self.shares_to_create);

        let mut dests: Vec<Box<dyn Write>> = Vec::with_capacity(self.shares_to_create);

        for path in file_paths {
            let f = File::create(path)?;
            dests.push(Box::new(f) as Box<dyn Write>);
        }

        self.share(&mut dests)?;

        if let Prime::NonDefault(_) = &self.prime {
            let prime_file_path = generate_prime_file_path(dir, stem);
            let mut curr_file = File::create(prime_file_path)?;
            self.share_prime(&mut curr_file)?;
        }

        Ok(())
    }


    /// Tests the reconstruction of the shares as outputted via the $share_to_files function.
    /// $dir: The directory to output the temporary shares. Default is the current dir
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


    /// Gets an immutable reference to the secret
    pub fn get_secret<'a>(&'a self) -> &'a Secret {
        &self.secret
    }


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


impl SharerBuilder {
    
    /// Builds and returns the Sharer struct
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
    pub fn prime(mut self, prime: i64) -> Result<Self, (SharerError, Self)> {
        if primal_check::miller_rabin(prime as u64) {
            self.prime = Prime::NonDefault(prime);
            Ok(self)
        }
        else {
            Err((SharerError::NotPrime(prime), self))
        }
    }


    /// Use a specific prime, or if it isn't prime, fallback to the default prime
    pub fn prime_or_default(self, prime: i64) -> Self {
        match self.prime(prime) {
            Ok(builder) => builder,
            Err((_, mut builder)) => {
                builder.prime = Prime::Default(*DEFAULT_PRIME);
                builder
            }
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

    // Used to generate random primes
    fn gen_random_prime<T: Rng>(rng: &mut T) -> i64 {
        let mut maybe_prime: i64 = rng.gen_range(std::i16::MAX as u32, std::u32::MAX as u32) as i64;
        maybe_prime = maybe_prime | 1; // Ensure the number is odd
        while !primal_check::miller_rabin(maybe_prime as u64) {
            // Not prime, step down by 2
            maybe_prime = maybe_prime - 2;
        }

        maybe_prime
    }



    /// Sets the number of shares required for secret reconstruction
    /// Default: 3
    /// Must be >= 2, else $build() will fail
    pub fn shares_required(mut self, shares_required: usize) -> Self {
        self.shares_required = shares_required;
        if self.shares_required < self.shares_to_create {
            self.shares_to_create = shares_required;
        }
        self
    }

    /// Sets the number of shares to create.
    /// Default: 3
    /// Must be >= 2 AND  >= $shares_required, else $build() will fail
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
            prime: Prime::Default(*DEFAULT_PRIME),
        }

    }

}


/// Iterator that iterates over a given Secret, returning smaller segments of it at a time. Returns
/// Option<Result<Vec<u8>, Box<dyn Error>>> because file reads may fail, and in that case
/// Some(Err(_)) is returned. Iteration can continue, but the behavior is undefined as it may be
/// able to continue reading or may not depending on the initial error. See std::io::Error for
/// possible errors.
pub struct SecretIterator {
    // Rust thinks it's dead code because a ptr is pulled from it and then it's set but never accessed,
    // but the ptr is used to reconstruct a slice that is used as the reader.
    #[allow(dead_code)]
    secret: Option<Vec<u8>>, // If the secret is InMemory, this will be some vector
    reader: Box<dyn Read>, // reader is a reader of the vec in secret, or it's to an open file
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

/// Contains the secret, whether in file or in memory stored in a Vec of bytes. This can be used
/// for both sharing and reconstructing. When reconstructing, you can set it to reconstruct into
/// a Vec by setting it to InMemory, or you can set it to output to a file. 
/// For sharing, you can input a secret to be shared, either a file or a vec of bytes. 
#[derive(Debug)]
pub enum Secret {
    InMemory(Vec<u8>),
    InFile(String),
    //Other(Box<dyn Read>), to be implemented soon
}

impl Secret {

    /// Constructs an empty vec for the secret. 
    pub fn empty_in_memory() -> Self {
        Secret::InMemory(Vec::new())
    }
    
    /// Constructs an empty vec for the secret but allocates an intial capacity.
    pub fn empty_in_memory_with_capacity(capacity: usize) -> Self {
        Secret::InMemory(Vec::with_capacity(capacity))
    }

    /// Points the secret to a file. This file can either be a source for the secret, or an output
    /// file for reconstructing a secret
    pub fn point_at_file(path: &str) -> Self {
        Secret::InFile(String::from(path))
    }

    /// Attempts to get the length of the Secret. This can fail if the secret is a file path that
    /// doesn't exist.
    pub fn len(&self) -> Result<u64, Box<dyn Error>> {
        match self {
            Secret::InFile(ref path) => Ok(std::fs::metadata(path)?.len()),
            Secret::InMemory(vec) => Ok(vec.len() as u64),
        }
    }


    /// Calculates and returns the Sha3-512 hash of the first 64 bytes of the secret. 
    /// This is mainly used for verifying secret reconstruction, where the chances of incorrect
    /// reconstruction resulting in the first 64 bytes being correct is extremely low. 
    ///
    /// If $secret.len() is less than 64 bytes, then only $secret.len() number of bytes is used.
    pub fn calculate_hash(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut hasher_output = [0u8; 64];
        let mut hasher = Sha3::sha3_512();
        let hash_input_num_bytes = if self.len()? < (NUM_FIRST_BYTES_FOR_VERIFY as u64) {
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
                input_vec.extend_from_slice(&secret[0..hash_input_num_bytes]);   
            },
        }
        hasher.input(input_vec.as_slice());
        hasher.result(&mut hasher_output);
        Ok(hasher_output.to_vec())

    }

    /// Calculcates and returns the hash of the first 64 bytes of the share in a string with
    /// hexidecimal digits. 
    pub fn get_hash_hex(&self) -> Result<String, Box<dyn Error>> {
        Ok(hex::encode(self.calculate_hash()?))
    }

    /// Calculates a hash and compares it to the given hash. Returns Ok(true) if they're
    /// equivalent, Ok(false) if they aren't or an error if there was an issue calculating the hash
    /// (likely a read error if Secret was a file)
    pub fn verify(&self, hash: &[u8]) -> Result<bool, Box<dyn Error>> {
        Ok(self.calculate_hash()? == hash.to_vec())
    }


    /// Reconstructs a secret from a given list of srcs. The srcs should all read the same number
    /// of bytes. 
    /// $src_len MUST be an accurate length of the shares
    pub fn reconstruct_from_srcs(&mut self, srcs: &mut Vec<Box<dyn Read>>, prime: Option<Box<dyn Read>>, 
                                 src_len: u64) -> Result<(), Box<dyn Error>> {
        let src_len = u64::try_from((src_len as i64) - 64)?; 
        // 64 is the hash len, which we don't want to include in the output secret, just to verify 
        // that the secret was reconstructed properly. This should never underflow if valid shares
        // are given.
       

        // Closure that converts bytes to i64 points
        let to_u32_points = |vec: Vec<u8>, segment_num: i64| -> Result<Vec<Point>, Box<dyn Error>> {
            u8_vec_to_u32(vec)?
                .into_iter()
                .map(|val| Ok(Point::new(segment_num, val)))
                .collect()
        };



        let prime = match prime {
            Some(mut reader) => {
                let mut buf = [0u8; 8];
                reader.read_exact(&mut buf)?;
                Prime::NonDefault(i64::from_be_bytes(buf))
            },
            None => Prime::Default(*DEFAULT_PRIME),
        };

        let mut dest: Box<dyn Write> = match self {
            Secret::InMemory(ref mut vec) => Box::new(vec) as Box<dyn Write>,
            Secret::InFile(ref path) => Box::new(File::create(path)?) as Box<dyn Write>,
        };

        let mut byte_counter = 0;
        while (byte_counter as i64) < ((src_len as i64) - READ_SEGMENT_SIZE as i64) {
            let mut segments: Vec<Vec<Point>> = Vec::with_capacity(srcs.len());
            // Read in one segment size from each share
            let mut segment_ctr = 1;
            for src in srcs.into_iter() {
                let mut buf: Vec<u8> = Vec::with_capacity(READ_SEGMENT_SIZE);
                src.take(READ_SEGMENT_SIZE as u64).read_to_end(&mut buf)?;


                
                // Seperate the vec into chunks an convert those chunks to i64 and map them to
                // points
                let conv_to_points: Vec<Point> = to_u32_points(buf, segment_ctr)?;


                segments.push(conv_to_points);
                segment_ctr = segment_ctr + 1; // Keeps track of the x_values for each segment                  
            }

            // Now segments has a segment from each share src, reconstruct the secret up to that
            // point and write it to the destination
            dest.write_all(
                &u32_vec_to_bytes(reconstruct_secrets_from_share_lists_u32(segments, *prime, srcs.len())?))?;

            byte_counter = byte_counter + READ_SEGMENT_SIZE as u64;

        }


        // We are now on the last segment which includes the hash at the end.
        // 
        let remaining_secret_bytes: usize = (src_len - byte_counter) as usize; 
        let excess_bytes = remaining_secret_bytes % std::mem::size_of::<u32>();
        let mut segments: Vec<Vec<Point>> = Vec::with_capacity(srcs.len());
        let mut hash_segments: Vec<Vec<Point>> = Vec::with_capacity(srcs.len());
        let mut excess_segments: Vec<Vec<Point>> = Vec::with_capacity(srcs.len());

        let mut segment_ctr = 1;
        for src in srcs.into_iter() {
            let mut buf: Vec<u8> = Vec::with_capacity(remaining_secret_bytes - excess_bytes);
            let mut hash = [0u8; 64];
            src.take((remaining_secret_bytes - excess_bytes) as u64).read_to_end(&mut buf)?;
            segments.push(to_u32_points(buf.to_vec(), segment_ctr)?);
            
            // Now handle the excess bytes if any
            if excess_bytes > 0 {
                let mut excess_buf: Vec<u8> = Vec::with_capacity(excess_bytes);
                src.take(excess_bytes as u64).read_to_end(&mut excess_buf)?;
                excess_segments.push(excess_buf.into_iter().map(|y| Point::new(segment_ctr, y)).collect());
            }
            
            // Now read in the hash     
            src.read_exact(&mut hash)?; 
            hash_segments.push(to_u32_points(hash.to_vec(), segment_ctr)?);
            
            // Incremenet the segment counter since we are moving on to the next segment 
            segment_ctr = segment_ctr + 1;



        }
        // Reconstruct the points from the bytes in the shares

        dest.write_all(
            &u32_vec_to_bytes(reconstruct_secrets_from_share_lists_u32(segments, *prime, srcs.len())?))?;
        if excess_bytes > 0 {
            dest.write_all(&reconstruct_secrets_from_share_lists(excess_segments, *prime, srcs.len())?)?;
        }
        let recon_hash = u32_vec_to_bytes(
            reconstruct_secrets_from_share_lists_u32(hash_segments, *prime, srcs.len())?);

        // Drop dest since if it is a file, we will be re-opening it to read from it to
        // calculate the hash. Ensure output is flushed
        dest.flush().ok();
        std::mem::drop(dest);
        if !self.verify(recon_hash.as_slice())? {
            
            let calc_hash_hex = hex::encode(self.calculate_hash()?);
            let orig_hash_hex = hex::encode(&recon_hash);
            return Err(Box::new(SharerError::VerificationFailure(orig_hash_hex, calc_hash_hex)));
        }

    
       Ok(())
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
        let mut share_files: Vec<Box<dyn Read>> = unwrapped_share_files.into_iter()
                                                         .map(|file| Box::new(file) as Box<dyn Read>)
                                                         .collect();


        let prime: Option<Box<dyn Read>> = match prime_location {
            PrimeLocation::InFile => 
                Some(Box::new(File::open(generate_prime_file_path(dir, stem))?) as Box<dyn Read>),
            PrimeLocation::Default => None,
        };
        
        let mut secret_path = Path::new(dir).to_path_buf();
        secret_path.push(stem);

        self.reconstruct_from_srcs(&mut share_files, prime, len)

    }

}



/// Defines a prime as either THE default prime, or a NonDefault one either generated or given
/// statically. If the default one is used it doesn't make sense to write it to a file
#[derive(Debug, Clone)]
enum Prime {
    Default(i64),
    NonDefault(i64),
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




// Auxiliary methods;


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

#[derive(Debug)]
struct ConvError(String);
impl std::fmt::Display for ConvError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl Error for ConvError {}


fn u32_vec_to_bytes(vec: Vec<u32>) -> Vec<u8> {
    vec.into_iter()
        .map(|val| val.to_be_bytes().to_vec())
        .flatten()
        .collect::<Vec<u8>>()
}


fn u8_vec_to_u32(vec: Vec<u8>) -> Result<Vec<u32>, ConvError> {
    if vec.len() % std::mem::size_of::<u32>() != 0 {
        return Err(ConvError(format!("Number of bytes for conversion must be mod 8 Given: {}",
                                          vec.len()))); 
    }
    Ok(vec.as_slice()
        .chunks(std::mem::size_of::<u32>())
        .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<u32>>())
}




#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[cfg(feature = "file_tests")]
    #[test]
    fn large_file_test() {
        env_logger::builder().is_test(true).try_init().unwrap();
        
        let start_sharing = Instant::now();
        
        let dir = "./";
        let stem = "test.txt";
        let num_shares = 2;
        let secret = Secret::InFile(String::from("./test.txt"));
        let sharer = Sharer::builder(secret)
                            .shares_required(num_shares)
                            .shares_to_create(num_shares)
                            .build()
                            .unwrap();
        sharer.share_to_files(dir, stem).unwrap();
        let mut recon = Secret::InFile(String::from("./test.txt.recon"));

        let elap_sharing = start_sharing.elapsed().as_millis();

        let start_recon = Instant::now();
        recon.reconstruct_from_files(dir, stem, num_shares, PrimeLocation::Default).unwrap();
        let elap_recon = start_recon.elapsed().as_millis();
        println!(
"Read Segment Size; {}
 Sharing time elapsed: {}
 Recon time elapsed: {}
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~",
 READ_SEGMENT_SIZE,
 elap_sharing,
 elap_recon);
    }
                                   

    
    #[test]
    fn basic_share_reconstruction() {


        let dir = "./";
        let stem = "basic_share_reconstruction_test";
        let num_shares = 2;
        let secret: Vec<u8> = vec![13, 240, 189];    
        let sharer = Sharer::builder(Secret::InMemory(secret))
            .shares_required(num_shares)
            .shares_to_create(num_shares)
            .build()
            .unwrap();
        sharer.share_to_files(dir, stem).unwrap();
        
        let mut recon = Secret::empty_in_memory();

        recon.reconstruct_from_files(dir, stem, num_shares, PrimeLocation::Default).map_err(|_| ()).ok();

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


    #[test]
    fn zero_test() {
        let dir = "./";
        let stem = "zero_test";
        let num_shares = 3;
        let secret: Vec<u8> = vec![0];
        let sharer = Sharer::builder(Secret::InMemory(secret))
            .shares_required(num_shares)
            .shares_to_create(num_shares)
            .build()
            .unwrap();
        sharer.share_to_files(dir, stem).unwrap();
        let mut recon = Secret::empty_in_memory();
        recon.reconstruct_from_files(dir, stem, num_shares, PrimeLocation::Default).unwrap();

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
            (Secret::InMemory(orig), Secret::InMemory(recon)) => {
                assert_eq!(orig, recon);
            }
            _ => panic!("Not both in memory"),
        }
    }



    #[cfg(feature = "benchmark_tests")]
    #[test]
    fn stress_test_sharer() {
        /*
        use rand::Rng;
        use rand::rngs::StdRng;
        use rand::SeedableRng*/
        let mut secret_buf = [0u8; 67];
        let dir = "./";
        let stem = ".stress_test_sharer";
        let num_shares = 8;
        let mut rand = StdRng::from_entropy();

        for i in 0..10000 {
            println!("RUN NUMBER: {}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~", i);
            rand.fill(&mut secret_buf[..]);
            std::fs::write("./stress_test_original", &mut secret_buf[..]).unwrap();
            let sharer = Sharer::builder(Secret::InMemory(secret_buf.clone().to_vec()))
                                                .shares_required(num_shares)
                                                .shares_to_create(num_shares)
                                                .build()
                                                .unwrap();
            sharer.share_to_files(dir, stem).unwrap();
            let mut recon = Secret::point_at_file("./stress_test_recon");
            recon.reconstruct_from_files(dir, stem, num_shares, PrimeLocation::Default).unwrap();
        }
    }


}







