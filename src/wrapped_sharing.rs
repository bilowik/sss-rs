use crate::basic_sharing::{from_secrets, reconstruct_secrets};
use sha3::digest::generic_array::GenericArray;
use sha3::digest::FixedOutput;
use sha3::Digest;
use std::convert::TryFrom;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

const NUM_FIRST_BYTES_FOR_VERIFY: usize = 32;
pub const READ_SEGMENT_SIZE: usize = 8_192; // 8 KB, which has shown optimal perforamnce

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
    pub fn len(&self) -> Result<u64, Error> {
        match self {
            Secret::InFile(ref path) => Ok(std::fs::metadata(path)
                .map_err(|e| Error::secret_file_error(self, e))?
                .len()),
            Secret::InMemory(vec) => Ok(vec.len() as u64),
        }
    }

    pub fn is_empty(&self) -> Result<bool, Error> {
        Ok(self.len()? == 0)
    }

    /// Calculates and returns the Sha3-512 hash of the first 64 bytes of the secret.
    ///
    /// This is mainly used for verifying secret reconstruction, where the chances of incorrect
    /// reconstruction resulting in the first 64 bytes being correct is extremely low.
    ///
    /// If $secret.len() is less than 64 bytes, then only $secret.len() number of bytes is used.
    pub fn calculate_hash(&self) -> Result<Vec<u8>, Error> {
        let mut hasher_output = *GenericArray::from_slice(&[0u8; 64]);
        let mut hasher = sha3::Sha3_512::new();
        let len = self.len()?;
        let hash_input_num_bytes = if len < (NUM_FIRST_BYTES_FOR_VERIFY as u64) {
            len as usize
        } else {
            NUM_FIRST_BYTES_FOR_VERIFY
        };

        let mut input_vec = Vec::with_capacity(hash_input_num_bytes);

        match self {
            Secret::InFile(ref path) => {
                let f = File::open(path).map_err(|e| Error::secret_file_error(self, e))?;
                f.take(hash_input_num_bytes as u64)
                    .read_to_end(&mut input_vec)
                    .map_err(|e| Error::secret_file_error(self, e))?;
            }
            Secret::InMemory(ref secret) => {
                input_vec.extend_from_slice(&secret[0..hash_input_num_bytes]);
            }
        }
        hasher.update(input_vec.as_slice());
        hasher.finalize_into(&mut hasher_output);
        Ok(hasher_output.to_vec())
    }

    /// Calculcates and returns the hash of the first 64 bytes of the share in a string with
    /// hexidecimal digits.
    pub fn get_hash_hex(&self) -> Result<String, Error> {
        Ok(hex::encode(self.calculate_hash()?))
    }

    /// Calculates a hash and compares it to the given hash.
    /// Returns Ok(true) if they're
    /// equivalent, Ok(false) if they aren't or an error if there was an issue calculating the hash
    /// (likely a read error if Secret was a file)
    pub fn verify(&self, hash: &[u8]) -> Result<bool, Error> {
        Ok(self.calculate_hash()? == hash.to_vec())
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
            Secret::InMemory(ref mut secret) => Some(std::mem::take(secret)),
            _ => None,
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
            _ => None,
        }
    }

    /// Unwrap if InMemory, or read into a Vec if it is InFile.
    ///
    /// This will return an Error if the file length is too large to fit into a Vec,
    /// or if the file path is invalid.
    pub fn unwrap_to_vec(self) -> Result<Vec<u8>, Error> {
        match self {
            Secret::InMemory(secret) => Ok(secret),
            Secret::InFile(path) => std::fs::read(&path)
                .map_err(|e| Error::FileError(String::from(path.to_str().unwrap()), e)),
        }
    }

    /// Unwrap and clone if InMemory, or read into a Vec if it is InFile.
    ///
    /// This will return an Error if the file length is too large to fit into a Vec,
    /// or if the file path is invalid.
    pub fn unwrap_to_vec_clone(&self) -> Result<Vec<u8>, Error> {
        match self {
            Secret::InMemory(ref secret) => Ok(secret.clone()),
            Secret::InFile(path) => {
                std::fs::read(path).map_err(|e| Error::secret_file_error(self, e))
            }
        }
    }
}

/// Iterator that iterates over a given Secret, returning smaller segments of it at a time.
///
/// Returns Option<Result<Vec<u8>, Error>> because file reads may fail, and in that case
/// Some(Err(_)) is returned.
///
/// Iteration can continue, but the behavior is undefined as it may be
/// able to continue reading or may not depending on the initial error. See std::io::Error for
/// possible errors.
pub struct SecretIterator {
    reader: Box<dyn Read>, // reader is a reader of the vec in secret, or it's to an open file
    path: Option<PathBuf>,
}

impl std::iter::IntoIterator for &Secret {
    type Item = Result<Vec<u8>, Error>;
    type IntoIter = SecretIterator;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Secret::InFile(ref path) => SecretIterator {
                // Figure out better way to handle this
                reader: Box::new(File::open(path).unwrap()) as Box<dyn Read>,
                path: Some(path.clone()),
            },
            Secret::InMemory(ref boxed_slice) => SecretIterator {
                reader: Box::new(std::io::Cursor::new(boxed_slice.clone())) as Box<dyn Read>,
                path: None,
            },
        }
    }
}

impl std::iter::Iterator for SecretIterator {
    type Item = Result<Vec<u8>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes_to_read = std::mem::size_of::<u8>() * READ_SEGMENT_SIZE;
        let mut result = Vec::with_capacity(bytes_to_read);
        if let Err(e) = (&mut self.reader)
            .take(bytes_to_read as u64)
            .read_to_end(&mut result)
        {
            // Return the error if an error ocurred during reading the next segment
            return Some(Err(match self.path {
                Some(ref path) => Error::FileError(String::from(path.to_str().unwrap()), e),
                _ => e.into(),
            }));
        }
        if result.is_empty() {
            return None;
        }
        Some(Ok(result))
    }
}

/// Shares all the shares to individual writable destinations.
///
/// This iterates through the
/// secret and calculates the share lists in chunks and writes the shares to their respective
/// destinations
///
/// **verify**: If true, a hash is calculated from the secret and placed at the end to be used
///             to verify reconstruction of the secret.
pub fn share_to_writables<'a>(
    secret: Secret,
    dests: &mut Vec<Box<dyn Write + 'a>>,
    shares_required: u8,
    shares_to_create: u8,
    verify: bool,
) -> Result<(), Error> {
    // This just writes each corresponding share_list in share_lists to a dest in dests. This
    // is written here as a closure since it's used at two different points in this function
    let share_lists_to_dests =
        |lists: Vec<Vec<(u8, u8)>>, dests: &mut Vec<Box<dyn Write + 'a>>| -> Result<(), Error> {
            for (share_list, dest) in lists.into_iter().zip(dests.iter_mut()) {
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
    for (x_val, dest) in dests.iter_mut().enumerate() {
        dest.write_all(&[(x_val + 1) as u8])?;
    }

    if dests.len() < (shares_to_create as usize) {
        // Not enough dests to share shares to
        return Err(Error::NotEnoughWriteableDestinations(
            dests.len(),
            shares_to_create,
        ));
    }
    for secret_segment in (&secret).into_iter() {
        // Return error if seret_segment is an error, or unwrap it if its ok. This can happen
        // if the secret is a file and a reading error occured during iteration
        let secret_segment = secret_segment?;

        if !secret_segment.is_empty() {
            let share_lists = from_secrets(
                secret_segment.as_slice(),
                shares_required,
                shares_to_create,
                None,
            )?;
            share_lists_to_dests(share_lists, dests)?;
        }

        std::mem::drop(secret_segment); // ensure the memory DOES get dropped
    }

    if verify {
        // Now that all of the shares have been written to, calculate the hash and share the hash
        // to the dests
        let hash: Vec<u8> = secret.calculate_hash()?.to_vec();
        let share_lists = from_secrets(&hash, shares_required, shares_to_create, None)?;

        // The shares for the hash have been created, write them all to dests
        share_lists_to_dests(share_lists, dests)?;
    }

    // Flush writes to all dests to ensure all bytes are written
    for dest in dests.iter_mut() {
        dest.flush().ok();
    }
    Ok(())
}

// TODO: Optimize me, there is a full copy that's done on all the shares, there must be a way to
// avoid this.
/// Creates the shares and places them into a Vec of Vecs. This wraps around
/// [share_to_writables].
pub fn share(
    secret: Secret,
    shares_required: u8,
    shares_to_create: u8,
    verify: bool,
) -> Result<Vec<Vec<u8>>, Error> {
    let share_len = secret.len()? + 1 + 64;
    if share_len > std::usize::MAX as u64 {
        return Err(Error::SecretTooLarge(secret.len()?));
    }
    let share_len = share_len as usize;

    let mut dests = Vec::with_capacity(shares_to_create as usize);
    let share_vec: Vec<u8> = Vec::with_capacity(share_len);
    for _ in 0..shares_to_create {
        let share_vec_clone = share_vec.clone();
        dests.push(Box::new(share_vec_clone) as Box<dyn Write>);
    }

    share_to_writables(
        secret,
        &mut dests,
        shares_required,
        shares_to_create,
        verify,
    )?;
    unsafe {
        Ok(dests
            .into_iter()
            .map(|dest| std::mem::transmute::<&Box<dyn Write>, &Box<Vec<u8>>>(&dest).to_vec())
            .collect())
    }
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
pub fn share_to_files<T: AsRef<Path>>(
    secret: Secret,
    dir: T,
    stem: &str,
    shares_required: u8,
    shares_to_create: u8,
    verify: bool,
) -> Result<(), Error> {
    let file_paths = generate_share_file_paths(dir, stem, shares_to_create);

    let mut dests: Vec<Box<dyn Write>> = Vec::with_capacity(shares_to_create as usize);

    for path in file_paths {
        let f = File::create(path)?;
        dests.push(Box::new(f) as Box<dyn Write>);
    }

    share_to_writables(
        secret,
        &mut dests,
        shares_required,
        shares_to_create,
        verify,
    )
}

/// Reconstructs a secret from a given list of shares.
///
/// **verify**: If true, a hash is assumed to exist at the end of the secret and will be used
///             to verify secret reconstruction. NOTE: This will fail if the secret was not
///             shared with verify set to true.
pub fn reconstruct(secret: &mut Secret, srcs: Vec<Vec<u8>>, verify: bool) -> Result<(), Error> {
    let src_len = srcs[0].len() as u64;
    let mut srcs = srcs
        .into_iter()
        .map(|share| Box::new(Cursor::new(share)) as Box<dyn Read>)
        .collect();
    reconstruct_from_srcs(secret, &mut srcs, src_len, verify)
}

/// Reconstructs a secret from a given list of srcs. The srcs should all read the same number
/// of bytes.
/// **src_len** MUST be an accurate length of the shares
pub fn reconstruct_from_srcs<'a>(
    secret: &mut Secret,
    srcs: &mut Vec<Box<dyn Read + 'a>>,
    src_len: u64,
    verify: bool,
) -> Result<(), Error> {
    // This is to avoid multiple reference issues.
    let to_points = |vec: Vec<u8>, segment_num: u8| -> Vec<(u8, u8)> {
        vec.into_iter().map(|val| (segment_num, val)).collect()
    };
    let get_shares = |num_bytes: usize,
                      srcs: &mut Vec<Box<dyn Read + 'a>>,
                      x_vals: &Vec<u8>|
     -> Result<Vec<Vec<(u8, u8)>>, Error> {
        let mut segments: Vec<Vec<(u8, u8)>> = Vec::with_capacity(srcs.len());

        // Read in one segment size from each share
        for (src, x_val) in srcs.iter_mut().zip(x_vals) {
            let mut buf: Vec<u8> = Vec::with_capacity(num_bytes as usize);
            src.take(num_bytes as u64).read_to_end(&mut buf)?;
            segments.push(to_points(buf, *x_val));
        }
        Ok(segments)
    };

    // First, get the first byte from each share, which is the x value for those shares
    let mut buf = Vec::with_capacity(1);
    let mut x_vals = Vec::with_capacity(srcs.len());
    for src in srcs.iter_mut() {
        buf.clear();
        src.take(1)
            .read_to_end(&mut buf)
            .map_err(|e| Error::secret_file_error(secret, e))?;
        x_vals.push(buf[0]);
    }

    let src_len = if verify {
        u64::try_from((src_len as i64) - 64 - 1).unwrap()
    } else {
        u64::try_from((src_len as i64) - 1).unwrap()
    };

    let segments_to_read = if src_len % (READ_SEGMENT_SIZE as u64) != 0 {
        (src_len / (READ_SEGMENT_SIZE as u64)) + 1
    } else {
        src_len / (READ_SEGMENT_SIZE as u64)
    } as usize;

    // 64 is the hash len, which we don't want to include in the output secret, just to verify
    // that the secret was reconstructed properly. This should never underflow if valid shares
    // are given since src_len will always be N + 64 where N is the share size

    let mut dest: Box<dyn Write> = match secret {
        Secret::InMemory(ref mut vec) => Box::new(vec) as Box<dyn Write>,
        Secret::InFile(ref path) => {
            Box::new(File::create(path).map_err(|e| Error::secret_file_error(secret, e))?)
                as Box<dyn Write>
        }
    };

    // Now read in segments and compute the secrets and write the secrets to the destination
    // Skip the last segment for now since it includes the appended hash
    let mut curr_len = src_len;
    if segments_to_read > 0 {
        while curr_len > 0 {
            let segment_size = if curr_len < (READ_SEGMENT_SIZE as u64) {
                curr_len as usize
            } else {
                READ_SEGMENT_SIZE
            };
            let segments = get_shares(segment_size, srcs, &x_vals)?;
            // Now segments has a segment from each share src, reconstruct the secret up to that
            // point and write it to the destination
            dest.write_all(reconstruct_secrets(segments)?.as_slice())?;
            curr_len = curr_len.saturating_sub(READ_SEGMENT_SIZE as u64);
        }
    }

    if verify {
        // Now read in the hash
        let hash_segments = get_shares(512, srcs, &x_vals)?;
        let recon_hash = reconstruct_secrets(hash_segments)?;
        // Drop dest since if it is a file, we will be re-opening it to read from it to
        // calculate the hash. Ensure output is flushed
        dest.flush().ok();
        std::mem::drop(dest);
        if !secret.verify(recon_hash.as_slice())? {
            let calc_hash_hex = hex::encode(secret.calculate_hash()?);
            let orig_hash_hex = hex::encode(&recon_hash);
            return Err(Error::VerificationFailure(orig_hash_hex, calc_hash_hex));
        }
    }
    Ok(())
}

/// Performs the reconstruction of the shares from files with in the given **dir** with the give **stem**
pub fn reconstruct_from_files<T: AsRef<Path>>(
    secret: &mut Secret,
    dir: T,
    stem: &str,
    shares_required: u8,
    verify: bool,
) -> Result<(), Error> {
    let share_paths = generate_share_file_paths(&dir, stem, shares_required);
    let share_files: Vec<Result<File, Error>> = share_paths
        .into_iter()
        .map(|path| File::open(&path).map_err(|e| Error::FileError(String::from(&path), e)))
        .collect();

    // Check that all the share files opened properly
    let mut unwrapped_share_files: Vec<File> = Vec::with_capacity(share_files.len());
    for file in share_files {
        unwrapped_share_files.push(file?);
    }
    // An error here would be extremely rare, so just panic.
    let len = unwrapped_share_files[0]
        .metadata()
        .expect("An error occured after opening file for read.")
        .len();

    // Now map the files to a dyn Read, which needed to wait till we got the len since Read
    // doesn't have a len method.
    let mut share_files: Vec<Box<dyn Read>> = unwrapped_share_files
        .into_iter()
        .map(|file| Box::new(file) as Box<dyn Read>)
        .collect();

    let mut secret_path = dir.as_ref().to_path_buf();
    secret_path.push(stem);

    reconstruct_from_srcs(secret, &mut share_files, len, verify)
}

#[derive(Debug)]
pub enum Error {
    ReconstructionNotEqual,
    EmptySecret,
    InvalidNumberOfShares(u8),
    NotEnoughWriteableDestinations(usize, u8),
    InvalidNumberOfBytesFromSource(u8),
    VerificationFailure(String, String),
    SecretTooLarge(u64),
    FileError(String, std::io::Error),
    IOError(std::io::Error),
    OtherSharingError(crate::basic_sharing::Error),
}

impl From<crate::basic_sharing::Error> for Error {
    fn from(source: crate::basic_sharing::Error) -> Self {
        Error::OtherSharingError(source)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::ReconstructionNotEqual => write!(
                f,
                "Reconstructed secret is not equivalent to initial secret"
            ),
            Error::EmptySecret => write!(
                f,
                "Cannot share an empty secret. Secret cannot have a length of 0"
            ),
            Error::InvalidNumberOfShares(given) => write!(
                f,
                "Must create at least 2 shares for sharing. Given: {}",
                given
            ),
            Error::NotEnoughWriteableDestinations(given, needed) => write!(
                f,
                "Need {} writable destinations for shares, only given {}",
                needed, given
            ),
            Error::InvalidNumberOfBytesFromSource(bytes) => write!(
                f,
                "Excess trailing bytes, must be divisible by {}. Trailing: {}",
                8, bytes
            ),
            Error::VerificationFailure(original_hash, calculated_hash) => write!(
                f,
                "Verification of reconstructed secret failed. Mismatched hashes:
Original Hash: {}
Calculated Hash: {}",
                original_hash, calculated_hash
            ),
            Error::SecretTooLarge(secret_len) => write!(
                f,
                "Cannot fit secret into a Vec since it exceeds usize max. Secret length: {}",
                secret_len
            ),
            Error::FileError(path, source) => {
                write!(f, "File with path '{}' could not be used: {}", path, source)
            }
            Error::IOError(source) => {
                write!(f, "IOError: '{}'", source)
            }
            Error::OtherSharingError(source) => {
                write!(f, "{}", source)
            }
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    fn secret_file_error(secret: &Secret, e: std::io::Error) -> Self {
        match secret {
            Secret::InFile(ref path) => Error::FileError(String::from(path.to_str().unwrap()), e),
            _ => Error::FileError(String::from("<Non-File-based IO Error>"), e),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Self {
        Error::IOError(source)
    }
}

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
        share_to_files(
            Secret::InMemory(secret.clone()),
            dir,
            stem,
            num_shares,
            num_shares,
            true,
        )
        .unwrap();

        let mut recon = Secret::empty_in_memory();

        reconstruct_from_files(&mut recon, dir, stem, num_shares, true)
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

        assert_eq!(secret, recon.unwrap_vec());
    }

    #[test]
    fn zero_test() {
        let num_shares = 3;
        let secret: Vec<u8> = vec![0];
        let shares = share(
            Secret::InMemory(secret.clone()),
            num_shares,
            num_shares,
            true,
        )
        .unwrap();
        let mut recon = Secret::empty_in_memory();
        reconstruct(&mut recon, shares, true).unwrap();

        assert_eq!(secret, recon.unwrap_vec());
    }

    #[test]
    fn shuffled_share_recon() {
        let secret = vec![10, 20, 30, 50];
        let num_shares = 6;
        let num_shares_required = 3;
        let mut shares = share(
            Secret::InMemory(secret.clone()),
            num_shares_required,
            num_shares,
            true,
        )
        .unwrap();
        shares.as_mut_slice().shuffle(&mut thread_rng());
        let mut recon_secret = Secret::empty_in_memory_with_capacity(secret.len());
        reconstruct(&mut recon_secret, shares[0..3].to_vec(), true).unwrap();

        assert_eq!(secret, recon_secret.unwrap_vec());
    }
}
