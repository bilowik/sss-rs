use crate::raw_share::*;
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use std::convert::{TryFrom};
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write, Cursor};
use std::path::{Path, PathBuf};

const NUM_FIRST_BYTES_FOR_VERIFY: usize = 32;
pub const READ_SEGMENT_SIZE: usize = 8_192; // 8 KB, which has shown optimal perforamnce

/// Creates shares from a given secret. Shares to any suitable destination that implements Write
/// and has conveinence functions for files. To instantiate, the [SharerBuilder] should be used.
#[derive(Debug)]
pub struct Sharer {
    secret: Secret, // The source of the secret, either an in memory vec or a file path
    shares_required: u8, // The number of shares required to reconstruct the secret
    shares_to_create: u8, // The number of shares to create
}

impl Sharer {
    /// Constructs the builder with defualt values. See the builder documentation for the default
    /// values.
    pub fn builder(secret: Secret) -> SharerBuilder {
        SharerBuilder {
            secret: secret,
            ..Default::default()
        }
    }
    
    /// Creates the shares and places them into a Vec of Vecs. This wraps around
    /// [share_to_writables].
    pub fn share(&self) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
        let share_len = self.secret.len()? + 1 + 64;
        if share_len > std::usize::MAX as u64 {
            return Err(Box::new(SharerError::SecretTooLarge(self.secret.len()?)));
        }
        let share_len = share_len as usize;

        let mut dests = Vec::with_capacity(self.shares_to_create as usize);
        let share_vec: Vec<u8> = Vec::with_capacity(share_len);
        for _ in 0..self.shares_to_create {
            let share_vec_clone = share_vec.clone();
            dests.push(Box::new(share_vec_clone) as Box<dyn Write>);
        }


        self.share_to_writables(&mut dests)?;
        unsafe {
            Ok(dests.into_iter()
               .map(|dest|  std::mem::transmute::<&Box<dyn Write>, &Box<Vec<u8>>>(&dest).to_vec()).collect())
       }



    }

    /// Shares all the shares to individual writable destinations.
    ///
    /// This iterates through the
    /// secret and calculates the share lists in chunks and writes the shares to their respective
    /// destinations
    pub fn share_to_writables(&self, mut dests: &mut Vec<Box<dyn Write>>) -> Result<(), Box<dyn Error>> {
        // This just writes each corresponding share_list in share_lists to a dest in dests. This
        // is written here as a closure since it's used at two different points in this function
        let share_lists_to_dests = |lists: Vec<Vec<(u8, u8)>>,
                                    mut dests: &mut Vec<Box<dyn Write>>|
         -> Result<(), Box<dyn Error>> {
            for (share_list, dest) in lists.into_iter().zip((&mut dests).into_iter()) {
                dest.write_all(
                    share_list
                        .into_iter()
                        .map(|(_, y)| y)
                        .collect::<Vec<u8>>()
                        .as_slice(),
                )?;
            }
            Ok(())
        };

        // Write out the x value to each dest that will be used for each following point
        for (x_val, dest) in dests.into_iter().enumerate() {
            dest.write(&[(x_val + 1) as u8])?;
        }

        if dests.len() < (self.shares_to_create as usize) {
            // Not enough dests to share shares to
            return Err(Box::new(SharerError::NotEnoughWriteableDestinations(
                dests.len(),
                self.shares_to_create,
            )));
        }
        for secret_segment in (&self.secret).into_iter() {
            // Return error if seret_segment is an error, or unwrap it if its ok. This can happen
            // if the secret is a file and a reading error occured during iteration
            let secret_segment = secret_segment?;

            if secret_segment.len() > 0 {

                let share_lists = create_share_lists_from_secrets(
                    secret_segment.as_slice(),
                    self.shares_required,
                    self.shares_to_create,
                    None
                )?;
                share_lists_to_dests(share_lists, &mut dests)?;
            }

            std::mem::drop(secret_segment); // ensure the memory DOES get dropped
        }

        // Now that all of the shares have been written to, calculate the hash and share the hash
        // to the dests
        let hash: Vec<u8> = self.secret.calculate_hash()?.to_vec();
        let share_lists =
            create_share_lists_from_secrets(&hash, self.shares_required, self.shares_to_create, None)?;

        // The shares for the hash have been created, write them all to dests
        share_lists_to_dests(share_lists, &mut dests)?;
        
        // Flush writes to all dests to ensure all bytes are written
        for dest in (&mut dests).into_iter() {
            dest.flush().ok();
        }
        Ok(())
    }

    /// Shares all the shares to separate files for distribution.This is a wrapper for the 
    /// [share_to_writables] function.
    ///
    /// Format: **dir**/**stem**.s<share_number>
    ///
    /// **stem:** Defines the stem of the output files, they will be stem.s0, stem.s1, and so on..
    ///
    /// **dir:** The directory to output the shares to.
    ///
    /// If **dir** isn't valid, the LAST invalid destination file's error is returned.
    pub fn share_to_files<T: AsRef<Path>>(&self, dir: T, stem: &str) -> Result<(), Box<dyn Error>> {
        let file_paths = generate_share_file_paths(dir, stem, self.shares_to_create);

        let mut dests: Vec<Box<dyn Write>> = Vec::with_capacity(self.shares_to_create as usize);

        for path in file_paths {
            let f = File::create(path)?;
            dests.push(Box::new(f) as Box<dyn Write>);
        }

        self.share_to_writables(&mut dests)
    }

    /// Tests the reconstruction of the shares as outputted via the $share_to_files function.
    ///
    /// **dir:** The directory to output the temporary shares. Default is the current dir
    pub fn test_reconstruction_file<T: AsRef<Path>>(&self, dir: Option<T>) -> Result<(), Box<dyn Error>> {
        let default_dir = Path::new("./");
        let dir: PathBuf = if let Some(dir) = dir {
            dir.as_ref().to_path_buf()
        }
        else {
            default_dir.to_path_buf()
        };

    

        let stem = ".tmp_share_file";

        let mut recon_secret = Secret::point_at_file(".tmp_secret_recon");

        self.share_to_files(&dir, stem)?;
        recon_secret.reconstruct_from_files(&dir, stem, self.shares_required)?;

        // Cleanup
        for path in generate_share_file_paths(&dir, stem, self.shares_required) {
            std::fs::remove_file(path).ok();
        }

        Ok(())
    }

    /// Gets an immutable reference to the secret
    pub fn get_secret<'a>(&'a self) -> &'a Secret {
        &self.secret
    }
}

/// The builder struct to give the Sharer struct  builder style construction.
///
/// Defaults:
/// - **shares_required:** 3
/// - **shares_to_create:** 3
#[derive(Debug)]
pub struct SharerBuilder {
    secret: Secret,       // The secret to be shared
    shares_required: u8,  // The number of shares needed to reconstruct the secret
    shares_to_create: u8, // The number of shares to generate
}

impl SharerBuilder {
    /// Builds and returns the Sharer struct
    pub fn build(self) -> Result<Sharer, Box<dyn Error>> {
        if self.secret.len()? == 0 {
            return Err(Box::new(SharerError::EmptySecret));
        }
        if self.shares_required < 2 || self.shares_to_create < 2 {
            return Err(Box::new(SharerError::InvalidNumberOfShares(
                self.shares_required,
            )));
        }

        Ok(Sharer {
            secret: self.secret,
            shares_required: self.shares_required,
            shares_to_create: self.shares_to_create,
        })
    }

    /// Sets the number of shares required for secret reconstruction
    ///
    /// Default: 3
    ///
    /// If set greater than shares_to_create, will set shares_to_create equal to it.
    /// Must be >= 2, else build() will fail
    pub fn shares_required(mut self, shares_required: u8) -> Self {
        self.shares_required = shares_required;
        if self.shares_required > self.shares_to_create {
            self.shares_to_create = shares_required;
        }
        self
    }

    /// Sets the number of shares to create.
    ///
    /// Default: 3
    ///
    /// If set less than shares_to_create, will set shares_required equal to it.
    /// Must be >= 2 AND  >= $shares_required, else $build() will fail
    pub fn shares_to_create(mut self, shares_to_create: u8) -> Self {
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
            shares_to_create: 3,
            shares_required: 3,
        }
    }
}

/// Iterator that iterates over a given Secret, returning smaller segments of it at a time.
///
/// Returns Option<Result<Vec<u8>, Box<dyn Error>>> because file reads may fail, and in that case
/// Some(Err(_)) is returned.
///
/// Iteration can continue, but the behavior is undefined as it may be
/// able to continue reading or may not depending on the initial error. See std::io::Error for
/// possible errors.
pub struct SecretIterator {
    reader: Box<dyn Read>, // reader is a reader of the vec in secret, or it's to an open file
}

impl std::iter::IntoIterator for &Secret {
    type Item = Result<Vec<u8>, Box<dyn Error>>;
    type IntoIter = SecretIterator;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Secret::InFile(ref path) => SecretIterator {
                reader: Box::new(File::open(path).unwrap()) as Box<dyn Read>,
            },
            Secret::InMemory(ref boxed_slice) => SecretIterator {
                reader: Box::new(std::io::Cursor::new(boxed_slice.clone())) as Box<dyn Read>,
            },
        }
    }
}

impl std::iter::Iterator for SecretIterator {
    type Item = Result<Vec<u8>, Box<dyn Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes_to_read = std::mem::size_of::<u8>() * READ_SEGMENT_SIZE;
        let mut result = Vec::with_capacity(bytes_to_read);
        if let Err(e) = (&mut self.reader)
            .take(bytes_to_read as u64)
            .read_to_end(&mut result)
        {
            // Return the error if an error ocurred during reading the next segment
            return Some(Err(Box::new(e) as Box<dyn Error>));
        }

        if result.len() == 0 {
            return None;
        }
        Some(Ok(result))
    }
}

/// Contains the secret, whether in file or in memory stored in a Vec of bytes.
///
/// This can be used for both sharing and reconstructing. When reconstructing,
/// you can set it to reconstruct into
/// a Vec by setting it to InMemory, or you can set it to output to a file.
/// For sharing, you can input a secret to be shared, either a file or a vec of bytes.
///
/// For example, setting it to empty in memory, and then reconstructing it, will place 
/// the reconstructed value in memory, whereas setting it to a file will place it 
/// in the path of the given file.
#[derive(Debug)]
pub enum Secret {
    InMemory(Vec<u8>),
    InFile(PathBuf),
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

    /// (u8, u8)s the secret to a file. This file can either be a source for the secret, or an output
    /// file for reconstructing a secret
    pub fn point_at_file<T: Into<PathBuf>>(path: T) -> Self {
        Secret::InFile(path.into())
    }

    /// Attempts to get the length of the Secret.
    ///
    /// This can fail if the secret is a file path that doesn't exist.
    pub fn len(&self) -> Result<u64, Box<dyn Error>> {
        match self {
            Secret::InFile(ref path) => Ok(std::fs::metadata(path)?.len()),
            Secret::InMemory(vec) => Ok(vec.len() as u64),
        }
    }

    /// Calculates and returns the Sha3-512 hash of the first 64 bytes of the secret.
    ///
    /// This is mainly used for verifying secret reconstruction, where the chances of incorrect
    /// reconstruction resulting in the first 64 bytes being correct is extremely low.
    ///
    /// If $secret.len() is less than 64 bytes, then only $secret.len() number of bytes is used.
    pub fn calculate_hash(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut hasher_output = [0u8; 64];
        let mut hasher = Sha3::sha3_512();
        let hash_input_num_bytes = if self.len()? < (NUM_FIRST_BYTES_FOR_VERIFY as u64) {
            self.len()? as usize
        } else {
            NUM_FIRST_BYTES_FOR_VERIFY
        };

        let mut input_vec = Vec::with_capacity(hash_input_num_bytes);

        match self {
            Secret::InFile(ref path) => {
                let f = File::open(path)?;
                f.take(hash_input_num_bytes as u64)
                    .read_to_end(&mut input_vec)?;
            }
            Secret::InMemory(ref secret) => {
                input_vec.extend_from_slice(&secret[0..hash_input_num_bytes]);
            }
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

    /// Calculates a hash and compares it to the given hash.
    /// Returns Ok(true) if they're
    /// equivalent, Ok(false) if they aren't or an error if there was an issue calculating the hash
    /// (likely a read error if Secret was a file)
    pub fn verify(&self, hash: &[u8]) -> Result<bool, Box<dyn Error>> {
        Ok(self.calculate_hash()? == hash.to_vec())
    }

    /// Reconstructs a secret from a given list of shares.
    pub fn reconstruct(&mut self, srcs: Vec<Vec<u8>>) -> Result<(), Box<dyn Error>> {
        let src_len = srcs[0].len() as u64;
        let mut srcs = srcs.into_iter()
                           .map(|share| Box::new(Cursor::new(share)) as Box<dyn Read>).collect();
        self.reconstruct_from_srcs(&mut srcs, src_len)
    }

    /// Reconstructs a secret from a given list of srcs. The srcs should all read the same number
    /// of bytes.
    /// **src_len** MUST be an accurate length of the shares
    pub fn reconstruct_from_srcs(
        &mut self,
        mut srcs: &mut Vec<Box<dyn Read>>,
        src_len: u64,
    ) -> Result<(), Box<dyn Error>> {
        let to_points = |vec: Vec<u8>, segment_num: u8| -> Vec<(u8, u8)> {
            vec.into_iter().map(|val| (segment_num, val)).collect()
        };

        let get_shares = |num_bytes: usize,
                          srcs: &mut Vec<Box<dyn Read>>,
                          x_vals: &Vec<u8>|
         -> Result<Vec<Vec<(u8, u8)>>, Box<dyn Error>> {
            let mut segments: Vec<Vec<(u8, u8)>> = Vec::with_capacity(srcs.len());

            // Read in one segment size from each share
            for (src, x_val) in srcs.into_iter().zip(x_vals) {
                let mut buf: Vec<u8> = Vec::with_capacity(num_bytes as usize);
                src.take(num_bytes as u64).read_to_end(&mut buf)?;
                segments.push(to_points(buf, *x_val));
            }
            Ok(segments)
        };

        // First, get the first byte from each share, which is the x value for those shares
        let mut buf = Vec::with_capacity(1);
        let mut x_vals = Vec::with_capacity(srcs.len());
        for src in srcs.into_iter() {
            buf.clear();
            src.take(1).read_to_end(&mut buf)?;
            x_vals.push(buf[0]);
        }


        let src_len = u64::try_from((src_len as i64) - 64 - 1)?;
        let segments_to_read = if src_len % (READ_SEGMENT_SIZE as u64) != 0 {
            (src_len / (READ_SEGMENT_SIZE as u64)) + 1
        } else {
            src_len / (READ_SEGMENT_SIZE as u64)
        } as usize;

        // 64 is the hash len, which we don't want to include in the output secret, just to verify
        // that the secret was reconstructed properly. This should never underflow if valid shares
        // are given since src_len will always be N + 64 where N is the share size

        let mut dest: Box<dyn Write> = match self {
            Secret::InMemory(ref mut vec) => Box::new(vec) as Box<dyn Write>,
            Secret::InFile(ref path) => Box::new(File::create(path)?) as Box<dyn Write>,
        };

        // Now read in segments and compute the secrets and write the secrets to the destination
        // Skip the last segment for now since it includes the appended hash
        if segments_to_read > 0 {
            for _ in 0..(segments_to_read - 1) {
                let segments = get_shares(READ_SEGMENT_SIZE, srcs, &x_vals)?;
                // Now segments has a segment from each share src, reconstruct the secret up to that
                // point and write it to the destination
                dest.write_all(reconstruct_secrets_from_share_lists(segments)?.as_slice())?;
            }
        }

        // If the secret isn't exactly divisible by READ_SEGMENT_SIZE, read the leftover bytes
        // and write the computed secret into dest
        let remaining_bytes = (src_len % (READ_SEGMENT_SIZE as u64)) as usize;
        if remaining_bytes > 0 {
            let last_segments = get_shares(remaining_bytes, &mut srcs, &x_vals)?;
            dest.write_all(reconstruct_secrets_from_share_lists(last_segments)?.as_slice())?;
        }

        // Now read in the hash
        let hash_segments = get_shares(512, &mut srcs, &x_vals)?;
        let recon_hash = reconstruct_secrets_from_share_lists(hash_segments)?;

        // Drop dest since if it is a file, we will be re-opening it to read from it to
        // calculate the hash. Ensure output is flushed
        dest.flush().ok();
        std::mem::drop(dest);
        if !self.verify(recon_hash.as_slice())? {
            let calc_hash_hex = hex::encode(self.calculate_hash()?);
            let orig_hash_hex = hex::encode(&recon_hash);
            return Err(Box::new(SharerError::VerificationFailure(
                orig_hash_hex,
                calc_hash_hex,
            )));
        }

        Ok(())
    }

    /// Performs the reconstruction of the shares from files with in the given **dir** with the give **stem**
    pub fn reconstruct_from_files<T: AsRef<Path>>(
        &mut self,
        dir: T,
        stem: &str,
        shares_required: u8,
    ) -> Result<(), Box<dyn Error>> {
        let share_paths = generate_share_file_paths(&dir, stem, shares_required);
        let share_files: Vec<Result<File, Box<dyn Error>>> = share_paths
            .into_iter()
            .map(|path| File::open(path).map_err(|e| Box::new(e) as Box<dyn Error>))
            .collect();

        // Check that all the share files opened properly
        let mut unwrapped_share_files: Vec<File> = Vec::with_capacity(share_files.len());
        for file in share_files {
            unwrapped_share_files.push(file?);
        }
        let len = unwrapped_share_files[0].metadata()?.len();

        // Now map the files to a dyn Read, which needed to wait till we got the len since Read
        // doesn't have a len method.
        let mut share_files: Vec<Box<dyn Read>> = unwrapped_share_files
            .into_iter()
            .map(|file| Box::new(file) as Box<dyn Read>)
            .collect();

        let mut secret_path = dir.as_ref().to_path_buf();
        secret_path.push(stem);

        self.reconstruct_from_srcs(&mut share_files, len)
    }

    /// Unwrap and return the inner vec, consuming the secret.
    ///
    /// This will panic if the underlying secret is InFile.
    pub fn unwrap_vec(mut self) -> Vec<u8> {
        self.try_unwrap_vec().unwrap()
    }

    /// Unwrap and clone the inner vec.
    ///
    /// This will panic if the underlying secret is InFile
    pub fn unwrap_vec_clone(&self) -> Vec<u8> {
        self.try_unwrap_vec_clone().unwrap()
    }

    /// Try to unwrap and return the inner vec.
    ///
    /// This does not consume self, since it may return None.
    ///
    /// If the secret is returned, an empty vec is put in its place.
    ///
    /// Returns None if the inner value is a path, else returns the secret.
    pub fn try_unwrap_vec(&mut self) -> Option<Vec<u8>> {
        match self {
            Secret::InMemory(ref mut secret) => Some(std::mem::replace(secret, Vec::new())),
            _ => None
        }
    }
    
    /// Try to unwrap and clone the inner vec.
    ///
    /// This does not consume self since it may return None.
    ///
    /// Returns None if the inner value is a path, else returns the secret.
    pub fn try_unwrap_vec_clone(&self) -> Option<Vec<u8>> {
        match self {
            Secret::InMemory(ref secret) => Some(secret.clone()),
            _ => None
        }
    }

    /// Unwrap if InMemory, or read into a Vec if it is InFile.
    ///
    /// This will return an Error if the file length is too large to fit into a Vec,
    /// or if the file path is invalid.
    pub fn unwrap_to_vec(self) -> Result<Vec<u8>, Box<dyn Error>> {
        match self {
            Secret::InMemory(secret) => Ok(secret),
            Secret::InFile(path) => std::fs::read(path).map_err(|e| e.into())
        }
    }
    
    /// Unwrap and clone if InMemory, or read into a Vec if it is InFile.
    ///
    /// This will return an Error if the file length is too large to fit into a Vec,
    /// or if the file path is invalid.
    pub fn unwrap_to_vec_clone(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        match self {
            Secret::InMemory(ref secret) => Ok(secret.clone()),
            Secret::InFile(path) => std::fs::read(path).map_err(|e| e.into())
        }
    }
}

#[derive(Debug, Clone)]
pub enum SharerError {
    ReconstructionNotEqual,
    EmptySecret,
    InvalidNumberOfShares(u8),
    NotEnoughWriteableDestinations(usize, u8),
    InvalidNumberOfBytesFromSource(u8),
    VerificationFailure(String, String),
    SecretTooLarge(u64)
}

impl std::fmt::Display for SharerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SharerError::ReconstructionNotEqual => write!(
                f,
                "Reconstructed secret is not equivalent to initial secret"
            ),
            SharerError::EmptySecret => write!(
                f,
                "Cannot share an empty secret. Secret cannot have a length of 0"
            ),
            SharerError::InvalidNumberOfShares(given) => write!(
                f,
                "Must create at least 2 shares for sharing. Given: {}",
                given
            ),
            SharerError::NotEnoughWriteableDestinations(given, needed) => write!(
                f,
                "Need {} writable destinations for shares, only given {}",
                needed, given
            ),
            SharerError::InvalidNumberOfBytesFromSource(bytes) => write!(
                f,
                "Excess trailing bytes, must be divisible by {}. Trailing: {}",
                8, bytes
            ),
            SharerError::VerificationFailure(original_hash, calculated_hash) => write!(
                f,
                "Verification of reconstructed secret failed. Mismatched hashes:
Original Hash: {}
Calculated Hash: {}",
                original_hash, calculated_hash
            ),
            SharerError::SecretTooLarge(secret_len) => write!(
                f,
                "Cannot fit secret into a Vec since it exceeds usize max. Secret length: {}",
                secret_len
            ),
        }
    }
}

impl Error for SharerError {}

// Auxiliary methods;

// Generates paths for the shares with in given dir with a given stem.
// It is assumed that dir is a valid directory, no checks are done.
fn generate_share_file_paths<T: AsRef<Path>>(dir: T, stem: &str, num_files: u8) -> Vec<String> {
    let mut path_buf = dir.as_ref().to_path_buf();
    let mut generated_paths: Vec<String> = Vec::with_capacity(num_files as usize);

    for i in 0..num_files {
        path_buf.push(format!("{}.s{}", stem, i));
        (&mut generated_paths).push(String::from(path_buf.to_str().unwrap()));
        path_buf.pop();
    }

    generated_paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::seq::SliceRandom;
    use rand::thread_rng;

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

        recon
            .reconstruct_from_files(dir, stem, num_shares)
            .map_err(|_| ())
            .ok();

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
        let num_shares = 3;
        let secret: Vec<u8> = vec![0];
        let sharer = Sharer::builder(Secret::InMemory(secret.clone()))
            .shares_required(num_shares)
            .shares_to_create(num_shares)
            .build()
            .unwrap();
        let shares = sharer.share().unwrap();
        let mut recon = Secret::empty_in_memory();
        recon.reconstruct(shares).unwrap();

        assert_eq!(secret, recon.unwrap_vec());

    }

    #[test]
    fn shuffled_share_recon() {
        let secret = vec![10, 20, 30, 50];
        let num_shares = 6;
        let num_shares_required = 3;
        let sharer = Sharer::builder(Secret::InMemory(secret.clone()))
            .shares_required(num_shares_required)
            .shares_to_create(num_shares)
            .build()
            .unwrap();
        let mut shares = sharer.share().unwrap();
        shares.as_mut_slice().shuffle(&mut thread_rng());
        let mut recon_secret = Secret::empty_in_memory_with_capacity(secret.len());
        recon_secret.reconstruct(shares[0..3].to_vec()).unwrap();
        
        assert_eq!(secret, recon_secret.unwrap_vec());
    }


}
