use crate::geometry::{GaloisPolynomial, Coeff};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

/// Creates a vector of points that serve as the list of shares for a given byte of data.
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
pub fn from_secret(
    secret: u8,
    shares_required: u8,
    shares_to_create: u8,
    rand: Option<&mut dyn RngCore>,
) -> Result<Vec<(u8, u8)>, Error> {
    Ok(from_secrets_no_points(&[secret], shares_required, shares_to_create, rand)?
        .into_iter()
        .map(|v| (v[0], v[1]))
        .collect())
}

/// Reconstructs a secret from a given Vector of shares (points) and returns that secret.
///
/// No guarantees are made that the shares are valid together and that the secret is valid.
/// If there are enough shares, reconstruction will succeed. 
pub fn reconstruct_secret(shares: Vec<(u8, u8)>) -> u8 {
    GaloisPolynomial::get_y_intercept_from_points(shares.as_slice())
}

/// This is a wrapper around [from_secret] and performs the same operation
/// but across each byte.
///
/// For additional documentation, see [from_secret]
///
/// **NOTE: Using predictable RNG can be a security risk. If unsure, use None.**
pub fn from_secrets(
    secret: &[u8],
    shares_required: u8,
    shares_to_create: u8,
    rand: Option<&mut dyn RngCore>,
) -> Result<Vec<Vec<(u8, u8)>>, Error> {
    if secret.is_empty() {
        return Err(Error::EmptySecretArray);
    }

    // If rand is None, create a new rand and return it's reference
    let mut from_entropy: Box<dyn RngCore>;
    let mut rand = match rand {
        Some(rng) => rng,
        None => {
            from_entropy = Box::new(StdRng::from_entropy());
            &mut from_entropy
        }
    };

    let mut list_of_share_lists: Vec<Vec<(u8, u8)>> = (0..shares_to_create).map(|_| Vec::with_capacity(secret.len())).collect();

    for s in secret {
        for (idx, share) in from_secret(*s, shares_required, shares_to_create, Some(&mut rand))?.into_iter().enumerate() {
            list_of_share_lists[idx].push(share);
        }
    }
    Ok(list_of_share_lists)
}

/// This is a wrapper around [reconstruct_secret] that iterates over each list of shares and
/// reconstructs their respective byte of the secret.
pub fn reconstruct_secrets(share_lists: Vec<Vec<(u8, u8)>>) -> Vec<u8> {
    let len = share_lists[0].len();
    (0..len).map(|idx| reconstruct_secret(share_lists.iter().map(|s| s[idx]).collect())).collect()
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
pub fn from_secrets_no_points(
    secret: &[u8],
    shares_required: u8,
    shares_to_create: u8,
    rand: Option<&mut dyn RngCore>,
) -> Result<Vec<Vec<u8>>, Error> {
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
    let mut shares_list = (0..shares_to_create).map(|_| Vec::with_capacity(secret.len() + 1))
        .enumerate()
        .map(|(i, mut v)| {
            v.push((i + 1) as u8); // This is the x coefficent of each share.
            v
        })
    .collect::<Vec<Vec<u8>>>();
    
    let polys = secret.iter().map(|s| {
        let mut share_poly = GaloisPolynomial::new();
        share_poly.set_coeff(Coeff(*s), 0);
        for i in 1..shares_required {
            let curr_co = rng.gen_range(2..255);
            share_poly.set_coeff(Coeff(curr_co), i as usize);
        }
        share_poly
    }).collect::<Vec<GaloisPolynomial>>();
    for x in 0..shares_to_create {
        for poly in polys.iter() {
            shares_list[x as usize].push(poly.get_y_value(x + 1));
        }
    }
    Ok(shares_list)
}

/// Wrapper around its [reconstruct_secrets], accepts shares created by [from_secrets_no_points]
/// function to reconstruct the secret from shares created using
/// [from_secrets_no_points]
///
/// The format the shares are to be in are as follows:
///
/// (1-byte X-value),(N-byte share)
///
/// See [reconstruct_secrets] for more documentation.
pub fn reconstruct_secrets_no_points(share_lists: Vec<Vec<u8>>) -> Vec<u8> {
    reconstruct_secrets(share_lists.into_iter().map(expand_share).collect())

}


fn expand_share(share: Vec<u8>) -> Vec<(u8, u8)> {
    let x_value = share[0];
    share[1..].iter().map(|y| (x_value, *y)).collect()
}

/// Transposes a Vec of Vecs if it is a valid matrix. If it is not an error is returned.
///
/// **matrix:** The matrix to be transposed, must be a valid matrix else an error is returned.
#[allow(clippy::needless_range_loop)]
pub fn transpose_vec_matrix<T: Clone>(matrix: Vec<Vec<T>>) -> Result<Vec<Vec<T>>, Error> {
    for i in 1..matrix.len() {
        if matrix[i - 1].len() != matrix[i].len() {
            return Err(Error::InvalidMatrix {
                index_of_invalid_length_row: i,
            });
        }
    }

    let col_len = matrix.len();
    let row_len = matrix[0].len();

    let mut transpose: Vec<Vec<T>> = Vec::with_capacity(col_len);

    for _ in 0..matrix[0].len() {
        transpose.push(Vec::with_capacity(row_len));
    }

    /*for i in 0..matrix.len() {
        for j in 0..matrix[i].len() {
            transpose[j].push(matrix[i][j].clone());
        }
    }*/
    for i in 0..matrix.len() {
        for j in 0..matrix[i].len() {
            transpose[j].push(matrix[i][j].clone());
        }
    }
    Ok(transpose)
}

/// Local Error enum, used to report errors that would only occur within this file.
#[derive(Debug)]
pub enum Error {
    NotEnoughShares { given: u8, required: u8 },
    InvalidMatrix { index_of_invalid_length_row: usize },
    InvalidNumberOfShares(u8),
    UnreconstructableSecret(u8, u8),
    EmptySecretArray,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::NotEnoughShares { given, required } => write!(
                f,
                "Not enough shares to recreate secret: Given: {}; Required: {}",
                given, required
            ),
            Error::InvalidMatrix {
                index_of_invalid_length_row,
            } => write!(
                f,
                "Row {} is not the same length as previous rows",
                index_of_invalid_length_row
            ),
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
    fn transpose() {
        let matrix = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];

        let matrix1 = vec![vec![1, 4, 7], vec![2, 5, 8], vec![3, 6, 9]];

        let matrix2 = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]];

        let matrix3 = vec![vec![1, 5], vec![2, 6], vec![3, 7], vec![4, 8]];

        assert_eq!(transpose_vec_matrix(matrix).unwrap(), matrix1);
        assert_eq!(transpose_vec_matrix(matrix2).unwrap(), matrix3);
    }

    #[cfg(feature = "benchmark_tests")]
    #[test]
    fn large_data_and_benchmark() {
        use std::time::Instant;

        let secret = "According to all known laws of aviation, 
            there is no way a bee should be able to fly.
            Its wings are too small to get its fat little body off the ground.
            The bee, of course, flies anyway
            because bees don't care what humans think is impossible.";
        let shares_required = 5;
        let shares_to_create = 5;

        let now = Instant::now();

        let share_lists =
            from_secrets(secret.as_bytes(), shares_required, shares_to_create).unwrap();

        let recon_secret_vec = reconstruct_secrets(share_lists).unwrap();
        let recon_secret = String::from_utf8(recon_secret_vec).unwrap();

        let time_elap = now.elapsed().as_millis();

        println!("Time elapsed: {} milliseconds", time_elap);

        assert_eq!(secret, &recon_secret[..])
    }

    #[test]
    fn no_points() {
        let secret = vec![10, 20, 30, 40, 50];
        let n = 3;
        let shares = from_secrets_no_points(&secret, n, n, None).unwrap();
        let recon = reconstruct_secrets_no_points(shares);
        assert_eq!(secret, recon);
    }
}
