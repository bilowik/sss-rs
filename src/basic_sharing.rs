//! Contains the core implementation of the library, in most cases [wrapped_sharing][crate::wrapped_sharing]
//! should be utilized, otherwise these functions are useful for implementing a custom abstraction/wrapper.
use crate::geometry::{Coeff, GaloisPolynomial};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

/// Creates a vector of points that serve as the list of shares for a given byte of data.
///
/// In a majority of cases if you are sharing more than a single byte, use [from_secrets] or
/// [from_secrets_compressed] for much greater efficiency.
///
/// ## Args
/// **secret:** The secret value that is to be split into shares
///
/// **shares_required:** The number of shares required to recreate the secret
///
/// **shares_to_create:** The number of shares to create, so any number 'x' shares from the total 'y'
/// shares are enough to recreate the secret. If < shares_required, it's automatically bumped up.
///
/// **rand:** The rng source for the generated coefficients in the sharing process.
/// The default is StdRng::from_entropy()
///
/// **NOTE: Using predictable RNG can be a security risk. If unsure, use None.**
///
pub fn from_secret(
    secret: u8,
    shares_required: u8,
    shares_to_create: u8,
    rand: Option<&mut dyn RngCore>,
) -> Result<Vec<(u8, u8)>, Error> {
    Ok(
        from_secrets_compressed(&[secret], shares_required, shares_to_create, rand)?
            .into_iter()
            .map(|v| (v[0], v[1]))
            .collect(),
    )
}

/// Reconstructs a secret from a given Vector of shares (points) and returns that secret.
///
/// No guarantees are made that the shares are valid together and that the secret is valid.
/// If there are enough shares, reconstruction will succeed.
pub fn reconstruct_secret<T: AsRef<[(u8, u8)]>>(shares: T) -> u8 {
    GaloisPolynomial::get_y_intercept_from_points(shares.as_ref())
}

/// This is a wrapper around [from_secret] and performs the same operation
/// but across each byte.
///
/// For additional documentation, see [from_secret]
///
/// **NOTE: Using predictable RNG can be a security risk. If unsure, use None.**
pub fn from_secrets<T: AsRef<[u8]>>(
    secret: T,
    shares_required: u8,
    shares_to_create: u8,
    rand: Option<&mut dyn RngCore>,
) -> Result<Vec<Vec<(u8, u8)>>, Error> {
    Ok(
        from_secrets_compressed(secret, shares_required, shares_to_create, rand)?
            .into_iter()
            .map(expand_share)
            .collect(),
    )
}

/// See [reconstruct_secret] for more information
///
/// This is a wrapper around [reconstruct_secret] that iterates over each list of shares and
/// reconstructs their respective byte of the secret.
///
/// Assumes each list is of equal length, passing lists with different lengths will result in
/// undefined behavior. If you need length checks, see [wrapped_sharing::reconstruct][crate::wrapped_sharing::reconstruct]
pub fn reconstruct_secrets<U: AsRef<[(u8, u8)]>, T: AsRef<[U]>>(share_lists: T) -> Vec<u8> {
    let share_lists = share_lists.as_ref();
    let len = share_lists[0].as_ref().len();
    let mut result = Vec::with_capacity(len);
    for idx in 0..len {
        result.push(reconstruct_secret(
            share_lists
                .iter()
                .map(|s| s.as_ref()[idx])
                .collect::<Vec<(u8, u8)>>(),
        ));
    }
    result
}

/// Wrapper around its corresponding share function but deduplicates the x-value
/// from all the points to reduce the size of the share.
///
/// Since each share is a collection of points, (u8, u8) where the x-value is identical
/// throughout the share, we can pull out the X value, which halves the size of the
/// share.
///
/// The format of the outputted shares are as follows:
///
/// (1-byte X-value),(N-byte share)
///
/// *For additional documentation, see [from_secrets]*
pub fn from_secrets_compressed<T: AsRef<[u8]>>(
    secret: T,
    shares_required: u8,
    shares_to_create: u8,
    rand: Option<&mut dyn RngCore>,
) -> Result<Vec<Vec<u8>>, Error> {
    let secret = secret.as_ref();
    if shares_required > shares_to_create {
        return Err(Error::UnreconstructableSecret(
            shares_to_create,
            shares_required,
        ));
    }

    if shares_to_create < 2 {
        return Err(Error::InvalidNumberOfShares(shares_to_create));
    }

    let mut rng: Box<dyn RngCore> = match rand {
        Some(rng) => Box::new(rng),
        None => Box::new(StdRng::from_entropy()),
    };

    // Create the vecs
    let mut shares_list = (0..shares_to_create)
        .map(|_| Vec::with_capacity(secret.len() + 1))
        .enumerate()
        .map(|(i, mut v)| {
            v.push((i + 1) as u8); // This is the x coefficent of each share.
            v
        })
        .collect::<Vec<Vec<u8>>>();
    for s in secret {
        let mut share_poly = GaloisPolynomial::new();
        share_poly.set_coeff(Coeff(*s), 0);
        for i in 1..shares_required {
            let curr_co = rng.gen_range(2..255);
            share_poly.set_coeff(Coeff(curr_co), i as usize);
        }
        for x in 0..shares_to_create {
            shares_list[x as usize].push(share_poly.get_y_value(x + 1))    
        }
    }
    Ok(shares_list)
}

/// Wrapper around its [reconstruct_secrets], accepts shares created by [from_secrets_compressed]
/// function to reconstruct the secret from shares created using
/// [from_secrets_compressed]
///
/// The format the shares are to be in are as follows:
///
/// (1-byte X-value),(N-byte share)
///
/// See [reconstruct_secrets] for more documentation.
pub fn reconstruct_secrets_compressed<U: AsRef<[u8]>, T: AsRef<[U]>>(share_lists: T) -> Vec<u8> {
    let share_lists = share_lists.as_ref();
    let len = share_lists[0].as_ref().len();
    let mut result = Vec::with_capacity(len);
    for idx in 1..len {
        result.push(reconstruct_secret(
            share_lists
                .iter()
                .map(|s| (s.as_ref()[0], s.as_ref()[idx]))
                .collect::<Vec<(u8, u8)>>(),
        ));
    }
    result
}

fn expand_share<T: AsRef<[u8]>>(share: T) -> Vec<(u8, u8)> {
    let share = share.as_ref();
    let x_value = share[0];
    share[1..].iter().map(|y| (x_value, *y)).collect()
}

#[derive(Debug)]
pub enum Error {
    /// shares_required was < 2
    InvalidNumberOfShares(u8),

    /// shares_required was > share_to_create
    UnreconstructableSecret(u8, u8),

    /// The given secret was empty
    EmptySecretArray,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::EmptySecretArray => write!(f, "Secret array should not be empty"),
            Error::InvalidNumberOfShares(num) => {
                write!(f, "Need to generate at least 2 shares. Requested: {}", num)
            }
            Error::UnreconstructableSecret(to_create, required) => write!(
                f,
                "Can't create less shares than required to reconstruct. Create: {}, Req: {}",
                to_create, required
            ),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;

    #[test]
    fn many_test() {
        let num_iters = 10;

        let mut rand = StdRng::seed_from_u64(123u64);

        for _ in 0..num_iters {
            let secret: u8 = rand.gen_range(1..256) as u8;
            let shares_required: u8 = rand.gen_range(2..10);
            let shares_to_create: u8 = shares_required + rand.gen_range(0..6);

            basic_single_value(secret, shares_to_create, shares_required);
        }
    }

    fn basic_single_value(secret: u8, shares_to_create: u8, shares_required: u8) {
        /* Was used to find an infinite loop, no longer needed, but keeping for future reference
        unsafe {
            register(signal_hook::SIGQUIT, || println!("{:?}", Backtrace::new()));
        }
        */

        let shares = from_secret(secret, shares_required, shares_to_create, None).unwrap();

        let secret_decrypted = reconstruct_secret(shares);
        assert_eq!(secret, secret_decrypted);
    }

    #[test]
    fn compressed() {
        let secret = vec![10, 20, 30, 40, 50];
        let n = 3;
        let shares = from_secrets_compressed(&secret, n, n, None).unwrap();
        let recon = reconstruct_secrets_compressed(shares);
        assert_eq!(secret, recon);
    }
}
