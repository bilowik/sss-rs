//! Abstractions and wrappers around the core implementation of sharing/reconstructing.
//!
//! For in-memory or small files, [share] and [reconstruct] are suitable. For large files or
//! byte streams, [Sharer] and [Reconstructor] are better suited since they share/reconstruct in
//! chunks.
//!
//! For implementing custom wrappers or abstractions, [basic_sharing][crate::basic_sharing]
//! functions can be utilized if finer-tuned control is needed.
use crate::basic_sharing::{from_secrets_compressed_inner, reconstruct_secrets_compressed};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use sha3::{Digest, Sha3_512};
use std::io::{BufRead, BufReader, Read, Write};

const DEFAULT_BUF_SIZE: usize = 1 << 22; // 4mb

/// Used to share in chunks, useful for large files.
///
///```
/// use sss_rs::wrapped_sharing::{Sharer, Reconstructor};
/// use std::io::Cursor;
///
/// let mut dest1 = Cursor::new(Vec::new());
/// let mut dest2 = Cursor::new(Vec::new());
/// let full_secret = b"This is a very long secret read in from a buffered file reader";
/// let secret_chunks = full_secret.chunks(8).collect::<Vec<&[u8]>>();
///
/// let mut sharer = Sharer::builder()
///     .with_shares_required(2)
///     .with_output(&mut dest1)
///     .with_output(&mut dest2)
///     .with_verify(true)
///     .build()
///     .unwrap();
///
/// for secret in secret_chunks.iter() {
///     sharer.update(secret).unwrap();
/// }
/// sharer.finalize().unwrap();
///```
///
pub struct Sharer<'a> {
    share_outputs: Vec<Box<dyn Write + 'a>>,
    bytes_shared: u64,
    hasher: Option<Sha3_512>,
    hash_op: fn(&mut Option<Sha3_512>, &[u8]),
    shares_required: u8,
    x_values: Vec<u8>,
}

/// Builder pattern for [Sharer], use [Sharer::builder] to instantiate.
pub struct SharerBuilder<'a> {
    share_outputs: Vec<Box<dyn Write + 'a>>,
    shares_required: u8,
    verify: bool,
}

impl<'a> Sharer<'a> {
    /// Creates a new instance of Sharer
    ///
    /// Susceptible to any underlying [std::io::Error] that can be produced by the underlying
    /// writable outputs.
    pub fn new(
        mut share_outputs: Vec<Box<dyn Write + 'a>>,
        shares_required: u8,
        verify: bool,
    ) -> Result<Self, Error> {
        if (share_outputs.len() < 2) || (share_outputs.len() < (shares_required as usize)) {
            return Err(Error::NotEnoughShareOutputs(
                share_outputs.len(),
                shares_required,
            ));
        }
        if share_outputs.len() > (u8::MAX as usize) {
            // This exceeds the number of shares we can create.
            return Err(Error::TooManyShareOutputs(share_outputs.len()));
        }
        let hash_op = if verify { add_to_hash } else { noop_hash };

        let mut all_x_values = (1u8..=255).collect::<Vec<u8>>();
        all_x_values.shuffle(&mut StdRng::from_entropy());
        let x_values = (0..share_outputs.len())
            .map(|idx| all_x_values[idx])
            .collect::<Vec<u8>>();

        // Write out the x value for each share
        for idx in 0..share_outputs.len() {
            share_outputs[idx].write(&[x_values[idx]])?;
        }
        Ok(Self {
            share_outputs,
            shares_required,
            hash_op,
            hasher: verify.then_some(Sha3_512::new()),
            bytes_shared: 0,
            x_values,
        })
    }

    pub fn builder() -> SharerBuilder<'a> {
        SharerBuilder::new()
    }

    pub fn get_shares_to_create(&self) -> u8 {
        self.share_outputs.len() as u8
    }

    pub fn get_shares_required(&self) -> u8 {
        self.shares_required as u8
    }

    /// Split the given chunk of data into shares and write them out to the
    /// set outputs.
    ///
    /// Susceptible to any underlying [std::io::Error] that can be produced by the underlying
    /// writable outputs.
    pub fn update<T: AsRef<[u8]>>(&mut self, data: T) -> Result<usize, Error> {
        let bytes = data.as_ref();
        let bytes_shared = bytes.len();
        (self.hash_op)(&mut self.hasher, bytes);

        for (share_list, output) in from_secrets_compressed_inner(
            data.as_ref(),
            self.shares_required,
            &self.x_values,
            None,
        )?
        .into_iter()
        .zip(self.share_outputs.iter_mut())
        {
            output.write_all(&share_list[1..])?;
        }
        self.bytes_shared += bytes_shared as u64;
        Ok(bytes_shared as usize)
    }

    /// Finalizes the sharing, and returns the number of bytes shared.
    ///
    /// If verify was set to true, the underlying hasher will produce a hash that is then also
    /// split into shares and written out to the set outputs.
    pub fn finalize(mut self) -> Result<u64, Error> {
        if let Some(hash) = self.hasher.as_mut().map(|hasher| hasher.finalize_reset()) {
            // We want to write out the hash as well.
            self.update(&hash)?;
        }
        Ok(self.bytes_shared)
    }
}

impl<'a> SharerBuilder<'a> {
    pub fn new() -> Self {
        Self {
            share_outputs: Vec::with_capacity(2),
            shares_required: 2,
            verify: false,
        }
    }

    /// Adds an output to the list of outputs to split the secret into
    pub fn with_output<T: Write + 'a>(mut self, output: T) -> Self {
        self.share_outputs
            .push(Box::new(output) as Box<dyn Write + 'a>);
        self
    }

    /// Appends the given outputs to the current list of outputs
    pub fn with_outputs<T: Write + 'a, I: IntoIterator<Item = T>>(mut self, outputs: I) -> Self {
        self.share_outputs.extend(
            outputs
                .into_iter()
                .map(|v| Box::new(v) as Box<dyn Write + 'a>),
        );
        self
    }

    /// Will calculate a hash of the secret and append it at the end, sharing it
    /// along with the secret, allowing for verification of valid reconstruction.
    pub fn with_verify(mut self, verify: bool) -> Self {
        self.verify = verify;
        self
    }

    /// Sets the number of shares required for reconstruction.
    ///
    /// This must not be < 2 or > the number of provided outputs. Default is 2 if unset.
    pub fn with_shares_required(mut self, shares_required: u8) -> Self {
        self.shares_required = shares_required;
        self
    }

    /// Instantiates the Sharer
    pub fn build(self) -> Result<Sharer<'a>, Error> {
        Sharer::new(self.share_outputs, self.shares_required, self.verify)
    }
}

fn add_to_hash(hasher: &mut Option<Sha3_512>, bytes: &[u8]) {
    hasher.as_mut().unwrap().update(bytes);
}

fn noop_hash(_hasher: &mut Option<Sha3_512>, _bytes: &[u8]) {}

/// Used to reconstruct a secret in chunks, useful for large files.
///
/// ```rust
/// use sss_rs::wrapped_sharing::{Sharer, Reconstructor};
/// use std::io::Cursor;
///
/// let mut dest1 = Cursor::new(Vec::new());
/// let mut dest2 = Cursor::new(Vec::new());
/// let full_secret = b"This is a very long secret read in from a buffered file reader";
///
/// # let secret_chunks = full_secret.chunks(8).collect::<Vec<&[u8]>>();
/// # let mut recon_dest = Cursor::new(Vec::new());
/// #
/// # let mut sharer = Sharer::builder()
/// #     .with_shares_required(2)
/// #     .with_output(&mut dest1)
/// #     .with_output(&mut dest2)
/// #     .with_verify(true)
/// #     .build()
/// #     .unwrap();
/// #
/// # for secret in secret_chunks.iter() {
/// #     sharer.update(secret).unwrap();
/// # }
/// # sharer.finalize().unwrap();
/// // *The secret is shared into dest1 and dest2...*
///
/// let mut reconstructor = Reconstructor::new(&mut recon_dest, true);
///
/// for (chunk1, chunk2) in dest1.get_ref().chunks(4).zip(dest2.get_ref().chunks(4)) {
///     reconstructor.update(&[chunk1, chunk2]).unwrap();
/// }
/// reconstructor.finalize().unwrap();
/// assert_eq!(&full_secret, &recon_dest.into_inner().as_slice());
/// ```
pub struct Reconstructor<'a> {
    secret_dest: Box<dyn Write + 'a>,
    hasher: Option<Sha3_512>,
    x_vals: Option<Vec<u8>>,
    update_inner: fn(&mut Reconstructor<'a>, &[&[u8]]) -> Result<(), Error>,
    hash_op: fn(&mut Option<Sha3_512>, &[u8]),
    last_64_bytes: Vec<u8>,
    bytes_reconstructed: u64,
}

impl<'a> Reconstructor<'a> {
    /// Creates a new instance of Reconstructor
    pub fn new<T: Write + 'a>(secret_dest: T, verify: bool) -> Self {
        let hash_op = if verify { add_to_hash } else { noop_hash };
        Self {
            secret_dest: Box::new(secret_dest) as Box<dyn Write + 'a>,
            hasher: verify.then_some(Sha3_512::new()),
            x_vals: None,
            update_inner: Reconstructor::first_update,
            hash_op,
            last_64_bytes: Vec::with_capacity(128),
            bytes_reconstructed: 0,
        }
    }

    /// Takes the given list of chunks and reconstructs a chunk of the secret, writing it to
    /// the set output.
    ///
    /// An error will be returned if all the blocks in blocks don't have identical lengths.
    ///
    /// Also susceptible to any underlying [std::io::Error] that can be produced by the underlying
    /// writable output.
    pub fn update<V: AsRef<[U]>, U: AsRef<[u8]>>(&mut self, blocks: V) -> Result<usize, Error> {
        let blocks = blocks.as_ref();
        if blocks.len() > (u8::MAX as usize) {
            return Err(Error::TooManyShareInputs(blocks.len()));
        }
        let lens: Vec<usize> = blocks.iter().map(|block| block.as_ref().len()).collect();

        if lens.iter().any(|len| len != &lens[0]) {
            return Err(Error::InconsistentSourceLength(lens));
        }
        (self.update_inner)(
            self,
            blocks
                .iter()
                .map(|b| b.as_ref())
                .collect::<Vec<&[u8]>>()
                .as_ref(),
        )?;
        self.bytes_reconstructed += lens[0] as u64;
        Ok(lens[0])
    }

    fn first_update(&mut self, blocks: &[&[u8]]) -> Result<(), Error> {
        // This includes the x-values
        self.x_vals = Some(blocks.iter().map(|b| b[0]).collect());
        self.update_inner = Reconstructor::non_first_update;
        self.non_first_update(
            blocks
                .iter()
                .map(|b| &b[1..])
                .collect::<Vec<&[u8]>>()
                .as_ref(),
        )?;
        Ok(())
    }

    fn non_first_update(&mut self, blocks: &[&[u8]]) -> Result<(), Error> {
        let expanded_blocks = blocks
            .iter()
            .zip(self.x_vals.as_ref().unwrap().iter())
            .map(|(block, x_val)| {
                std::iter::once(*x_val)
                    .chain(block.iter().copied())
                    .collect::<Vec<u8>>()
            })
            .collect::<Vec<Vec<u8>>>();

        let recon_chunk = reconstruct_secrets_compressed(expanded_blocks)?;

        // Split the recon_chunk into slices of [ X bytes ],[64 bytes]. The last 64 bytes
        // are stored and written in the next call to update, or during finalize when
        // hasher is None.
        // Tracking the last 64 bytes allows us to calculate the hash of the reconstructed
        // secret without having to re-read it.
        let curr_chunk = &recon_chunk[0..recon_chunk.len().saturating_sub(64)];
        let last_64_bytes = &recon_chunk[recon_chunk.len().saturating_sub(64)..];

        // Append the current last 64 with the new 64
        self.last_64_bytes.extend(last_64_bytes);

        // Drain so only the latest 64 elements remain, writing the ones drained off into the reconstructing secret
        // first, since they were reconstructed before the current chunk.
        let drained_recon_bytes = self
            .last_64_bytes
            .drain(0..self.last_64_bytes.len().saturating_sub(64))
            .collect::<Vec<u8>>();

        self.secret_dest.write_all(&drained_recon_bytes)?;
        self.secret_dest.write_all(curr_chunk)?;

        // Now hash, in the same order.
        (self.hash_op)(&mut self.hasher, &drained_recon_bytes);
        (self.hash_op)(&mut self.hasher, curr_chunk);

        Ok(())
    }
    /// Writes out any remaining bytes or calculates and compares hashes if verify was set.
    ///
    /// Returns the total number of bytes reconstructed. Note this is not the total number of bytes
    /// fed into the Reconstructor.
    ///
    /// Susceptible to any underlying [std::io::Error] that can be produced by the underlying
    /// writable output.
    pub fn finalize(mut self) -> Result<u64, Error> {
        if let Some(hasher) = self.hasher.as_mut() {
            // verify was enabled, so the last 64 bytes are assumed to be the hash.
            let calculated_hash = hasher.finalize_reset();
            if calculated_hash.as_slice() != &self.last_64_bytes {
                return Err(Error::VerificationFailure(
                    hex::encode(&calculated_hash),
                    hex::encode(&self.last_64_bytes),
                ));
            }
        } else {
            // verify was not enabled, so last 64 bytes still need to be written.
            self.secret_dest.write_all(&self.last_64_bytes)?;
        }

        Ok(self.bytes_reconstructed)
    }
}

/// See [from_secrets_compressed][crate::basic_sharing::from_secrets_compressed] for more
/// information.
///
/// Wraps around [from_secrets_compressed][crate::basic_sharing::from_secrets_compressed with the
/// option to use hash verification.
pub fn share<T: AsRef<[u8]>>(
    secret: T,
    shares_required: u8,
    shares_to_create: u8,
    verify: bool,
) -> Result<Vec<Vec<u8>>, Error> {
    let secret = secret.as_ref();
    let len = secret.len() + if verify { 64 } else { 0 };

    let mut outputs = (0..shares_to_create)
        .map(|_| Vec::with_capacity(len))
        .collect();

    share_buffered(
        secret,
        &mut outputs,
        shares_required,
        verify,
        Some(secret.len()),
    )?;

    Ok(outputs)
}

/// Convenience method for the common use case of using a BufReader with Sharer to share large
/// secrets.
///
/// For more flexible outputs, see [share_buffered_dyn]
/// Also see [Sharer] for more information.
pub fn share_buffered<T: Read, U: Write, V: AsMut<[U]>>(
    secret: T,
    mut outputs: V,
    shares_required: u8,
    verify: bool,
    buf_size: Option<usize>,
) -> Result<u64, Error> {
    let outputs_dyn = outputs
        .as_mut()
        .iter_mut()
        .map(|o| Box::new(o) as Box<dyn Write>)
        .collect::<Vec<_>>();
    share_buffered_dyn(secret, outputs_dyn, shares_required, verify, buf_size)
}

/// Convenience method for the common use case of using a BufReader with Sharer to share large
/// secrets. Takes a non-homogeneous list of outputs.
///
/// This wraps around [Sharer] and updates in chunks of buf_size or the default size of
/// 4MB if unspecified.
///
/// For outputs that all share the same type, see [share_buffered]
/// Also see [Sharer] for more information.
pub fn share_buffered_dyn<'a, T: Read, U: AsMut<[Box<dyn Write + 'a>]> + 'a>(
    secret: T,
    mut outputs: U,
    shares_required: u8,
    verify: bool,
    buf_size: Option<usize>,
) -> Result<u64, Error> {
    let mut sharer = Sharer::builder()
        .with_outputs(outputs.as_mut())
        .with_shares_required(shares_required)
        .with_verify(verify)
        .build()?;
    let mut buffered_secret =
        BufReader::with_capacity(buf_size.unwrap_or(DEFAULT_BUF_SIZE), secret);

    // Do while loop, which exits when consumed_len == 0, which means we reached the end of the
    // Read
    while {
        let num_bytes = {
            let curr_chunk = buffered_secret.fill_buf()?;
            sharer.update(curr_chunk)?;
            curr_chunk.len()
        };
        buffered_secret.consume(num_bytes);

        num_bytes > 0
    } {}

    sharer.finalize()
}

/// Convenience method for the common use case of using BufReaders with Reconstructor to
/// reconstrcut large secrets
///
/// This wraps around [Reconstructor] and updates in chunks of buf_size or the default size of
/// 4MB if unspecified. The inputs must provide the same number of total bytes.
///
/// For more flexibility for inputs, see [reconstruct_buffered_dyn]
/// Also see [Reconstructor] for more information.
pub fn reconstruct_buffered<T: Write, U: Read, V: AsMut<[U]>>(
    mut inputs: V,
    secret_dest: T,
    verify: bool,
    buf_size: Option<usize>,
) -> Result<u64, Error> {
    let inputs_dyn = inputs
        .as_mut()
        .iter_mut()
        .map(|i| Box::new(i) as Box<dyn Read>)
        .collect::<Vec<_>>();
    reconstruct_buffered_dyn(inputs_dyn, secret_dest, verify, buf_size)
}

/// Convenience method for the common use case of using BufReaders with Reconstructor to
/// reconstrcut large secrets
///
/// This wraps around [Reconstructor] and updates in chunks of buf_size or the default size of
/// 4MB if unspecified. The inputs must provide the same number of total bytes.
///
/// For inputs that all share the same type, see [reconstruct_buffered] for simpler usage.
/// Also see [Reconstructor] for more information.
pub fn reconstruct_buffered_dyn<'a, T: Write, U: AsMut<[Box<dyn Read + 'a>]> + 'a>(
    mut inputs: U,
    secret_dest: T,
    verify: bool,
    buf_size: Option<usize>,
) -> Result<u64, Error> {
    // We can either require AsMut, or IntoIterator here. Unusre of which is most
    // flexible for expected uses cases. We cannot use AsRef here bc Read is not
    // implemented for &Box<dyn Read>.
    let mut reconstructor = Reconstructor::new(secret_dest, verify);

    let mut buffered_inputs = inputs
        .as_mut()
        .iter_mut()
        .map(|v| BufReader::with_capacity(buf_size.unwrap_or(DEFAULT_BUF_SIZE), v))
        .collect::<Vec<_>>();

    // Do while loop, which exits when consumed_len == 0, which means we eached the end of the
    // Reads.
    while {
        let chunks: Vec<&[u8]> = buffered_inputs
            .iter_mut()
            .map(|buffered_input| buffered_input.fill_buf())
            .collect::<Result<Vec<&[u8]>, std::io::Error>>()?;
        let num_bytes = reconstructor.update(chunks)?;
        buffered_inputs
            .iter_mut()
            .for_each(|buffered_input| buffered_input.consume(num_bytes));

        num_bytes > 0
    } {}

    reconstructor.finalize()
}

/// Reconstructs a secret to a vec
pub fn reconstruct<U: AsRef<[u8]>, T: AsRef<[U]>>(srcs: T, verify: bool) -> Result<Vec<u8>, Error> {
    let guessed_size = srcs.as_ref().get(0).map(|s| s.as_ref().len()).unwrap_or(1);

    // If the below get() is None, then we will allow Reconstructor to throw the error.
    let mut output = Vec::with_capacity(guessed_size);

    reconstruct_buffered(
        srcs.as_ref()
            .iter()
            .map(|s| s.as_ref())
            .collect::<Vec<&[u8]>>(),
        &mut output,
        verify,
        Some(guessed_size),
    )?;

    Ok(output)
}

/// Error for wrapped_sharing API, any error marked with (deprecated) will not be encountered
/// if you avoid the deprecated functions.
#[derive(Debug)]
pub enum Error {
    /// An empty secret was provided
    EmptySecret,

    /// An invalid number of shares was provided, needs to be > 1
    InvalidNumberOfShares(u8),

    /// The calculated hash after reconstruction did not match the hash found at the end of the
    /// secret
    VerificationFailure(String, String),

    /// std::io::Error
    IOError(std::io::Error),

    /// An error from basic_sharing functions, see [crate::basic_sharing::Error]
    OtherSharingError(crate::basic_sharing::Error),

    /// During reconstruction, verify is set to true, but one or more of the inputs have < 65 bytes
    NotEnoughBytesInSrc(u64),

    /// During reconstruction, the given source chunks did not have equal lengths.
    InconsistentSourceLength(Vec<usize>),

    /// Occurs when < 2 share outputs are given or number of share outputs is less than the shares
    /// required.
    NotEnoughShareOutputs(usize, u8),

    /// Occurs when > 255 share outputs are given when constructing a Sharer
    TooManyShareOutputs(usize),

    /// Occurs when > 255 share inputs are given when constructing a Reconstructor
    TooManyShareInputs(usize),
}

impl From<crate::basic_sharing::Error> for Error {
    fn from(source: crate::basic_sharing::Error) -> Self {
        Error::OtherSharingError(source)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::EmptySecret => write!(
                f,
                "Cannot share an empty secret. Secret cannot have a length of 0"
            ),
            Error::InvalidNumberOfShares(given) => write!(
                f,
                "Must create at least 2 shares for sharing. Given: {}",
                given
            ),
            Error::VerificationFailure(original_hash, calculated_hash) => write!(
                f,
                "Verification of reconstructed secret failed. Mismatched hashes:
Original Hash: {}
Calculated Hash: {}",
                original_hash, calculated_hash
            ),
            Error::IOError(source) => {
                write!(f, "IOError: '{}'", source)
            }
            Error::OtherSharingError(source) => {
                write!(f, "{}", source)
            }
            Error::NotEnoughBytesInSrc(bytes) => {
                write!(
                    f,
                   "The given length ({}) is not long enough for reconstruction, must be >65 if verify, else >2", 
                   bytes
                )
            }
            Error::InconsistentSourceLength(lens) => {
                write!(f, "The given chunks have differing lengths: {:?}", lens,)
            }
            Error::NotEnoughShareOutputs(given, required) => {
                write!(
                    f,
                    "Need {} share outputs, only {} given. Must be > 2 and >= shares required",
                    given, required
                )
            }
            Error::TooManyShareOutputs(len) => {
                write!(f, "Cannot generate {} shares, max is {}", len, u8::MAX)
            }
            Error::TooManyShareInputs(len) => {
                write!(
                    f,
                    "Cannot reconstruct from {} shares, max is {}",
                    len,
                    u8::MAX
                )
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Self {
        Error::IOError(source)
    }
}

// Auxiliary methods;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};
    use std::io::{Cursor, Seek};

    #[test]
    fn base_functions() {
        let secret = vec![10, 20, 30, 50];
        let num_shares = 6;
        let num_shares_required = 3;
        let shares = share(&secret, num_shares_required, num_shares, true).unwrap();
        let recon_secret = reconstruct(&shares[0..3], true).unwrap();

        assert_eq!(secret, recon_secret);
    }

    #[test]
    fn max_shares_create() {
        let secret = vec![10, 20, 30, 50];
        let num_shares = 255;
        let num_shares_required = 3;
        let shares = share(&secret, num_shares_required, num_shares, true).unwrap();
        let recon_secret = reconstruct(&shares[0..3], true).unwrap();

        assert_eq!(secret, recon_secret);
    }

    #[test]
    fn max_shares_create_and_required() {
        let secret = vec![10, 20, 30, 50];
        let num_shares = 255;
        let num_shares_required = 255;
        let shares = share(&secret, num_shares_required, num_shares, true).unwrap();
        let recon_secret = reconstruct(&shares[0..3], true).unwrap();

        assert_eq!(secret, recon_secret);
    }

    #[test]
    fn base_functions_no_verify() {
        let secret = vec![10, 20, 30, 50];
        let num_shares = 6;
        let num_shares_required = 3;
        let shares = share(&secret, num_shares_required, num_shares, false).unwrap();
        let recon_secret = reconstruct(&shares[0..3], false).unwrap();

        assert_eq!(secret, recon_secret);
    }

    fn sharer_reconstructor_base<T: AsRef<[u8]> + Copy>(
        secret_chunks: &[T],
        shares_required: u8,
        shares_to_create: u8,
        verify: bool,
    ) {
        let mut share_dests = (0..shares_to_create)
            .map(|_| Cursor::new(Vec::new()))
            .collect::<Vec<Cursor<Vec<u8>>>>();
        let secret_chunks = secret_chunks
            .iter()
            .map(|s| s.as_ref())
            .collect::<Vec<&[u8]>>();
        let mut recon_dest = Cursor::new(Vec::new());

        let mut builder = Sharer::builder()
            .with_shares_required(shares_required)
            .with_verify(verify);

        for d in share_dests.iter_mut() {
            builder = builder.with_output(d);
        }
        let mut sharer = builder.build().unwrap();

        for secret in secret_chunks.iter() {
            sharer.update(secret).unwrap();
        }
        sharer.finalize().unwrap();

        let mut reconstructor = Reconstructor::new(&mut recon_dest, verify);
        reconstructor
            .update(
                &share_dests
                    .iter()
                    .map(|s| s.get_ref())
                    .collect::<Vec<&Vec<u8>>>(),
            )
            .unwrap();
        reconstructor.finalize().unwrap();
        let full_secret = secret_chunks
            .iter()
            .copied()
            .flatten()
            .copied()
            .collect::<Vec<u8>>();
        assert_eq!(&full_secret, &recon_dest.into_inner().as_slice());
    }

    #[test]
    fn sharer_reconstructor_small() {
        sharer_reconstructor_base(&[b"Hello world"], 2, 2, true);
    }

    #[test]
    fn sharer_reconstructor_large() {
        let secret = [b"Hello World"; 256]
            .iter()
            .copied()
            .flatten()
            .copied()
            .collect::<Vec<u8>>();
        sharer_reconstructor_base(&[&secret], 2, 2, true);
    }

    #[test]
    fn sharer_reconstructor_many_updates() {
        let secret = [b"Hello World"; 256];
        sharer_reconstructor_base(&secret, 2, 2, true);
    }

    #[test]
    fn sharer_reconstructor_many_updates_many_shares() {
        let secret = [b"Hello World"; 256];
        sharer_reconstructor_base(&secret, 3, 5, true);
    }
    #[test]
    fn sharer_reconstructor_no_verify() {
        let secret = [b"Hello World"; 256];
        sharer_reconstructor_base(&secret, 3, 5, false);
    }

    #[test]
    #[should_panic(expected = "VerificationFailure")]
    fn sharer_reconstructor_bad_shares() {
        let mut recon_dest = Cursor::new(Vec::new());
        let rando_shares = (0..2)
            .map(|_| thread_rng().gen::<[u8; 32]>())
            .collect::<Vec<[u8; 32]>>();
        let mut reconstructor = Reconstructor::new(&mut recon_dest, true);
        reconstructor.update(&rando_shares).unwrap();
        reconstructor.finalize().unwrap();
    }

    #[test]
    fn sharer_empty() {
        assert!(Sharer::builder().build().is_err());
    }

    #[test]
    fn buffered() {
        let secret_size = 8192;
        let mut secret = Cursor::new(
            (0..(secret_size / 32))
                .map(|_| thread_rng().gen::<[u8; 32]>())
                .fold(Vec::with_capacity(secret_size), |mut acc, v| {
                    acc.extend(v);
                    acc
                }),
        );
        let mut share_1 = Vec::with_capacity(secret_size + 1);
        let mut share_2 = Vec::with_capacity(secret_size + 1);

        // Could not for the life of me figure out how to get an iterator to do this with mutable
        // references.
        let outputs = [
            Box::new(&mut share_1) as Box<dyn Write>,
            Box::new(&mut share_2) as Box<dyn Write>,
        ];

        share_buffered_dyn(&mut secret, outputs, 2, true, Some(256)).unwrap();
        let mut recon_secret = Vec::with_capacity(secret_size);
        let inputs = [
            Box::new(Cursor::new(&share_1)) as Box<dyn Read>,
            Box::new(Cursor::new(&share_2)) as Box<dyn Read>,
        ];

        reconstruct_buffered(inputs, &mut recon_secret, true, Some(256)).unwrap();
        assert_eq!(secret.into_inner(), recon_secret);
    }

    #[test]
    fn buffered_empty() {
        let secret = Cursor::new(Vec::new());
        let mut outputs = (0..2).map(|_| Cursor::new(Vec::new())).collect::<Vec<_>>();
        share_buffered(secret, &mut outputs, 2, true, Some(256)).unwrap();
        outputs.iter_mut().for_each(|o| o.rewind().unwrap());
        let mut recon_secret = Vec::new();
        reconstruct_buffered(&mut outputs, &mut recon_secret, true, Some(256)).unwrap();
    }

    #[test]
    #[should_panic(expected = "InconsistentSourceLength")]
    fn buffered_bad_lens() {
        let secret = Cursor::new(b"Hello world");
        let mut outputs = (0..2).map(|_| Cursor::new(Vec::new())).collect::<Vec<_>>();
        share_buffered(secret, &mut outputs, 2, true, Some(256)).unwrap();
        outputs[1].write_all(b"oopsies").unwrap();
        outputs.iter_mut().for_each(|o| o.rewind().unwrap());
        let mut recon_secret = Vec::new();
        reconstruct_buffered(&mut outputs, &mut recon_secret, true, Some(256)).unwrap();
    }

    // Technically valid, but it just ends up being a 0-degree polynomial, each value is just a
    // constant so it gets spat right back out.
    #[test]
    fn reconstruct_from_one_share() {
        let shares = vec![vec![1, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50]];
        let mut output = Vec::new();
        let mut reconstructor = Reconstructor::new(&mut output, false);
        reconstructor.update(&shares).unwrap();
        reconstructor.finalize().unwrap();
    }

    #[test]
    #[should_panic(expected = "NotEnoughShareOutputs")]
    fn share_one_share() {
        Sharer::builder()
            .with_output(Vec::new())
            .with_shares_required(2)
            .build()
            .unwrap();
    }
}
