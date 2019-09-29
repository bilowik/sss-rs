use crate::geometry::*;
use rand::Rng;
use rand::rngs::StdRng;
use rand::{SeedableRng, FromEntropy};
//use std::ops::Rem;
use crypto::sha3::Sha3;
use crypto::digest::Digest;
use rand::seq::SliceRandom;
use rand_chacha::ChaChaRng;
use lazy_static::lazy_static;


lazy_static! {
    //pub static ref DEFAULT_PRIME: i64 = (2i64).pow(61) - 1; choosing a smaller prime
    pub static ref DEFAULT_PRIME: i64 = 5000000029;
    pub static ref CO_MIN: u32 = (2u32).pow(2);
    pub static ref CO_MAX: u32 = (2u32).pow(14); //2048
}



/// Creates a vector of points that serve as the list of shares for a given byte of data. 
/// @secret: The secret value that is to be split into shares
/// @prime: The prime number that is used to generate a finite field to increase security. This is
///     not checked to be prime, so no errors will be reported if this value isn't prime, which
///     must be done outside this function for efficiency. 
/// @shares_required: The number of shares required to recreate the secret
/// @shares_to_create: The number of shares to create, so any number 'x' shares from the total 'y'
///     shares are enough to recreate the secret. If < shares_required, it's automatically bumped
///     up.
/// @co_max_bits: The maximum number of bits for the randomly generated coefficients of the polynomial
///     hide the secret. If @co_max_bits == 0, this function will panic.
///
/// Return: This function will return Ok<Vec<Point>> upon success. 
pub fn create_shares_from_secret(secret: u8, _prime: i64, shares_required: usize, 
                        shares_to_create: usize) -> Result<Vec<Point>, Error> {

    let mut shares: Vec<Point> = Vec::new();
    let mut share_poly = Polynomial::new();
    
    let mut rand = StdRng::from_entropy();

    share_poly.set_term(Term::new(secret as i64, 0));

    for i in 1usize..shares_required {
        let curr_co: u32 = rand.gen_range(*CO_MIN, *CO_MAX);
        // Limiting the coefficient size to i16 lowers the risk of overflow when calculating y
        // values
        
        share_poly.set_term(Term::new(curr_co as i64, i));
    }
    

    for i in 1..=shares_to_create {
        let curr_x = Fraction::new(i as i64, 1);
        let curr_y: Fraction = share_poly.get_y_value(curr_x);
        shares.push(Point::new(curr_x, curr_y));
    }



    Ok(shares)
}


/// Reconstructs a secret from a given Vector of shares (points) and returns that secret. No
/// guarantees are made that the shares are valid together and that the secret is valid. If there
/// are enough shares, a secret will be generated.
/// @shares: The vector of shares that are used to regenerate the polynomial and finding the
///     secret. @shares.len() must be >= @shares_needed, else this will return an error.
/// @prime: The original prime used to generate the shares. No guarantees are made that this prime
///     is indeed the original prime, this must be kept from when the shares were generated. This
///     value is also not checked to be prime, which must be done outside this function for
///     efficieny.
///
/// This will return an error if @shares.len() < shares_needed.
pub fn reconstruct_secret(shares: Vec<Point>, _prime: i64, 
                          shares_needed: usize) -> Result<u8, Error> {
    match Polynomial::from_points(&shares, shares_needed - 1) {
        Ok(poly) => {
            Ok(poly.get_term(0).get_co().get_numerator() as u8)
            /*
            let secret = poly.get_term(0)
                            .get_co()
                            .get_numerator()
                            .rem(prime);
            // NaturalMod was used here, but when the secret is 0, would sometimes come out to be
            // 255, but isn't the case when the below is used instead. Why does it work? I honestly
            // don't know. I just noticed that the normal Rem function either was correct or 
            // left it exactly S off from 256, where S is the secret. The expression below takes
            // care of that.
            if secret.abs() < 256 {
                Ok(secret as u8)
            }
            else {
                Ok((256 - secret.abs()).abs() as u8)
            }
            */

        },
        Err(_) => Err(Error::NotEnoughShares { given: shares.len(), required: shares_needed }),
    }
}

// TODO: The transpose isn't the issue, other issues exist. Move to u64 or u128 per secret

/// This is a wrapper around @create_share_from_secret that loops through the @secret slice and
/// returns a vector of vectors, with each vector being all the shares for a single byte of the
/// secret.
/// The format this returns the secrets in is:
///     share1byte1, share1byte2, share1byte3, ..., share1byte<share_lists.len()> 
///     share2byte1, share2byte2, share2byte3, ..., share2byte<share_lists.len()>
/// since that is how they would be distributed.
/// @secret: A slice of bytes to be used to create the vector of share vectors
/// ... For the rest of the arguments, see @create_shares_from_secret
pub fn create_share_lists_from_secrets(secret: &[u8], prime: i64, shares_required: usize,
                                   shares_to_create: usize
                                   ) -> Result<Vec<Vec<Point>>, Error> {
    if secret.len() == 0 {
        return Err(Error::EmptySecretArray);
    }

    let mut list_of_share_lists: Vec<Vec<Point>> = Vec::with_capacity(secret.len());
    for s in secret {
        match create_shares_from_secret(*s, 
                                           prime, 
                                           shares_required,
                                           shares_to_create) {
            Ok(shares) => {
                // Now this list needs to be transposed:
                list_of_share_lists.push(shares);
            },
            Err(e) => {
                return Err(e);
            }
        }
    }
    let list_of_share_lists = transpose_vec_matrix(list_of_share_lists).unwrap();
    Ok(list_of_share_lists)
}


/// This is a wrapper around @reconstruct_secret that iterates over each Vec of shares and
/// reconstructs their respective byte of the secret.
/// It expects the shares to be in this format:
///     share1byte1, share1byte2, share1byte3, ..., share1byte<share_lists.len()> 
///     share2byte1, share2byte2, share2byte3, ..., share2byte<share_lists.len()>
/// since that is how they would be distributed.
/// @share_lists: A Vec of Vecs, with each Vec containing the shares needed to reconstruct a byte
///     of the secret.
/// ... For the rest of the arguments, see @reconstruct_secret
pub fn reconstruct_secrets_from_share_lists(share_lists: Vec<Vec<Point>>, prime: i64,
                                            shares_needed: usize) -> Result<Vec<u8>, Error> {
    let mut secrets: Vec<u8> = Vec::with_capacity(share_lists.len());
    let share_lists = transpose_vec_matrix(share_lists)?;
    for point_list in share_lists {
        match reconstruct_secret(point_list, prime, shares_needed) {
            Ok(secret) => {
                secrets.push(secret);
            },
            Err(e) => {
                return Err(e);
            }
        }
    }
    Ok(secrets)
}


   //TODO: Add initial capacities for vecs 
pub fn create_shares_from_secret_u32(secret: u32, _prime: i64, shares_required: usize, 
                        shares_to_create: usize) -> Result<Vec<Point>, Error> {

    let mut shares: Vec<Point> = Vec::new();
    let mut share_poly = Polynomial::new();
    
    let mut rand = StdRng::from_entropy();

    share_poly.set_term(Term::new(secret, 0));

    for i in 1usize..shares_required {
        let curr_co: u32 = rand.gen_range(*CO_MIN, *CO_MAX);
        // Limiting the coefficient size to i16 lowers the risk of overflow when calculating y
        // values
        
        share_poly.set_term(Term::new(curr_co as i64, i));
    }


    for i in 1..=shares_to_create {
        let curr_x = Fraction::new(i as i64, 1);
        let curr_y: Fraction = share_poly.get_y_value(curr_x);
        
        
        shares.push(Point::new(curr_x, curr_y));
    }

    Ok(shares)
}


pub fn reconstruct_secret_u32(shares: Vec<Point>, _prime: i64, 
                          shares_needed: usize) -> Result<u32, Error> {
    match Polynomial::from_points(&shares, shares_needed - 1) {
        Ok(poly) => {
            
            Ok(poly.get_term(0)
                        .get_co()
                        .get_numerator() as u32)
                        
            /*
            let secret = poly.get_term(0)
                            .get_co()
                            .get_numerator()
                            .rem(prime);
            if secret.abs() < (std::u32::MAX as i64) + 1 {
                Ok(secret as u32)
            }
            else {
                Ok(((std::u32::MAX as i64 + 1) - secret.abs()).abs() as u32)
            }
            */
        },
        Err(_) => Err(Error::NotEnoughShares { given: shares.len(), required: shares_needed }),
    }
}

/// Performs secret sharing but with i64 values as the inputted secrets. Improved performance vs
/// individual byte sharing, which should only be used on excess data that doesn't perfectly fit
/// into 8-bytes.
pub fn create_share_lists_from_secrets_u32(secret: &[u32], prime: i64, shares_required: usize, 
                                        shares_to_create: usize) -> Result<Vec<Vec<Point>>, Error> {
    if secret.len() == 0 {
        return Err(Error::EmptySecretArray);
    }

    let mut list_of_share_lists: Vec<Vec<Point>> = Vec::with_capacity(secret.len());
    for s in secret {
        match create_shares_from_secret_u32(*s,
                                            prime,
                                            shares_required,
                                            shares_to_create) {
            Ok(shares) => {
                list_of_share_lists.push(shares);
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    let list_of_share_lists = transpose_vec_matrix(list_of_share_lists).unwrap();
    Ok(list_of_share_lists)
}


pub fn reconstruct_secrets_from_share_lists_u32(share_lists: Vec<Vec<Point>>, prime: i64,
                                            shares_needed: usize) -> Result<Vec<u32>, Error> {
    let mut secrets: Vec<u32> = Vec::with_capacity(share_lists.len());
    let share_lists = transpose_vec_matrix(share_lists)?;
    for point_list in share_lists {
        match reconstruct_secret_u32(point_list, prime, shares_needed) {
            Ok(secret) => {
                secrets.push(secret);
            },
            Err(e) => {
                return Err(e);
            }
        }
    }
    Ok(secrets)
}











/// Used to specify the shuffle operation to be used, ReverseShuffle undoes Shuffle and vice-versa
/// when given the same hash.
#[derive(Debug, Copy, Clone)]
pub enum ShuffleOp {
    Shuffle,
    ReverseShuffle,
}

/// Shuffles the given shares with a rng seeded with the hash of a password. This would mean that
/// the shares would need to be unshuffled using the same password in order to restore the data
/// properly.
// The reason for the unsafe run-around with the vector is to save a bunch of extra copying of
// blank data into the vector to give it enough room to be indexed at random up to length
// @num_shares
fn shuffle_shares<T: Clone>(shares: Vec<T>, hashed_pass: &[u8; 32], shuffle: ShuffleOp) -> Vec<T> {
    let num_shares = shares.len();
    let mut shuffled = Vec::with_capacity(num_shares);
    let cap = shuffled.capacity();

    //let mut rand = ChaCha8Rng::from_seed(*hashed_pass);
    let mut rand = ChaChaRng::from_seed(*hashed_pass);

    let raw_vec_ptr: *mut T = shuffled.as_mut_ptr();
    std::mem::forget(shuffled);

    let mut indices: Vec<usize> = (0..num_shares).collect();
    indices.shuffle(&mut rand);

    match shuffle {
        ShuffleOp::Shuffle => {
            for it in (0..num_shares).zip(indices.iter()) {
                let (index, new_index) = it;
                unsafe {
                    std::ptr::write(raw_vec_ptr.offset(*new_index as isize), shares[index].clone());
                }
            }
        },
        ShuffleOp::ReverseShuffle => {
            for it in (0..num_shares).zip(indices.iter()) {
                let (index, new_index) = it;
                unsafe {
                    std::ptr::write(raw_vec_ptr.offset(index as isize), shares[*new_index].clone());
                }
            }
        }
    }

    unsafe {
        Vec::from_raw_parts(raw_vec_ptr, num_shares, cap)
    }
}


/// A wrapper around shuffle_shares which iterates through a list of share lists and shuffles each
/// one in the same way The share lists must be shuffled and unshuffled with the same password, 
/// no checking is done to ensure the password is correct.
/// PRECAUTION: Do not attempt to unshuffle without a copy of the original shuffled share lists so
/// if an incorrect password is accidentally entered and that copy is permamently corrupted, the
/// backup can be used to attempt it again. Some measures could also be taken for verification of
/// the unshuffled reconstructed share but that is left up to library users.
pub fn shuffle_share_lists<T: Clone>(share_lists: Vec<Vec<T>>, hashed_pass: &[u8], 
                           shuffle: ShuffleOp) -> Vec<Vec<T>> {
    let mut shuffled_share_lists: Vec<Vec<T>> = Vec::with_capacity(share_lists.len());

    let hashed_pass: [u8; 32] = if hashed_pass.len() == 256 {
        // The hashed pass is the proper length for seeding the RNG
        let mut s = [0u8; 32];
        s.copy_from_slice(hashed_pass);
        s
    }
    else {
        // Since the RNG accepts 256-bit input, expand (or retract) the given input by putting it
        // through SHA256 to get a 256-bit hash
        let mut hashed_output = [0; 32];
        let mut hasher = Sha3::sha3_256();
        hasher.input(hashed_pass);
        hasher.result(&mut hashed_output);
        hashed_output
    };



    for shares in share_lists {
        let shuffled_shares = shuffle_shares(shares, &hashed_pass, shuffle);
        shuffled_share_lists.push(shuffled_shares);
    }

    shuffled_share_lists

}



/// Transposes a Vec of Vecs if it is a valid matrix. If it is not an error is returned.
/// @matrix: The matrix to be transposed, must be a valid matrix else an error is returned.
pub fn transpose_vec_matrix<T: Clone>(matrix: Vec<Vec<T>>) -> Result<Vec<Vec<T>>, Error> {

    for i in 1..matrix.len() {
        if matrix[i - 1].len() != matrix[i].len() {
            return Err(Error::InvalidMatrix { index_of_invalid_length_row: i } );
        }
    }

    let col_len = matrix.len();
    let row_len = matrix[0].len();
    

    let mut transpose: Vec<Vec<T>> = Vec::with_capacity(col_len);

    for _ in 0..matrix[0].len() {
        transpose.push(Vec::with_capacity(row_len));
    }

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
    NotEnoughShares { given: usize, required: usize },
    InvalidMatrix { index_of_invalid_length_row: usize },
    EmptySecretArray,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::NotEnoughShares { given, required } => 
                write!(f, "Not enough shares to recreate secret: Given: {}; Required: {}", 
                       given, required),
            Error::InvalidMatrix { index_of_invalid_length_row } => 
                write!(f, "Row {} is not the same length as previous rows", index_of_invalid_length_row),
            Error::EmptySecretArray => write!(f, "Secret array should not be empty"),
        }
    }
}

impl std::error::Error for Error {}


#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::Rng;
    use super::*;
    use rand::rngs::SmallRng;

    #[test]
    fn many_test() {

        let num_iters = 10;
        let prime = *DEFAULT_PRIME;

        let mut rand = SmallRng::seed_from_u64(123u64);

        for _ in 0..num_iters {
            let secret: u8 = rand.gen_range(1, 256) as u8;
            let shares_required = rand.gen_range(2, 10);
            let shares_to_create = shares_required + rand.gen_range(0, 6);

            basic_single_value(secret, prime, shares_to_create, shares_required);
        }

    }


    fn basic_single_value(secret: u8, prime: i64, shares_to_create: usize, shares_required: usize) {

        /* Was used to find an infinite loop, no longer needed, but keeping for future reference
        unsafe {
            register(signal_hook::SIGQUIT, || println!("{:?}", Backtrace::new()));
        }
        */
        
        let shares = create_shares_from_secret(
                secret, 
                prime, 
                shares_required, 
                shares_to_create)
            .unwrap();

        let secret_decrypted = reconstruct_secret(shares, prime, shares_required).unwrap();
        assert_eq!(secret, secret_decrypted);

    }

    #[test]
    fn transpose() {
        let matrix = vec![
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9]
        ];

        let matrix1 = vec![
            vec![1, 4, 7],
            vec![2, 5, 8],
            vec![3, 6, 9]
        ];


        let matrix2 = vec![
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8]
        ];
         
        let matrix3 = vec![
            vec![1, 5],
            vec![2, 6],
            vec![3, 7],
            vec![4, 8]
        ];

        assert_eq!(transpose_vec_matrix(matrix).unwrap(), matrix1);
        assert_eq!(transpose_vec_matrix(matrix2).unwrap(), matrix3);
    }


    #[cfg(feature = "benchmark_tests")]    
    #[test]
    fn large_data_and_benchmark() {
        use std::time::Instant;

        let secret = 
            "According to all known laws of aviation, 
            there is no way a bee should be able to fly.
            Its wings are too small to get its fat little body off the ground.
            The bee, of course, flies anyway
            because bees don't care what humans think is impossible.";
        let shares_required = 5;
        let shares_to_create = 5;
        let prime = *DEFAULT_PRIME;

    
        let now = Instant::now();

        let share_lists = create_share_lists_from_secrets(secret.as_bytes(), prime, 
                          shares_required, shares_to_create).unwrap();

        let recon_secret_vec = reconstruct_secrets_from_share_lists(
                share_lists, prime, shares_required).unwrap();
        let recon_secret = String::from_utf8(recon_secret_vec).unwrap();
        
        let time_elap = now.elapsed().as_millis();

        println!("Time elapsed: {} milliseconds", time_elap);

        assert_eq!(secret, &recon_secret[..])

    }

    #[test]
    fn shuffle() {
        let secret = "Hello World";
        let pass = String::from("password");
        let mut hashed_pass = [0; 32];
        let mut hasher = Sha3::sha3_256();
        hasher.input(pass.as_bytes());
        hasher.result(&mut hashed_pass);

        let prime: i64 = *DEFAULT_PRIME;
        let share_lists = create_share_lists_from_secrets(secret.as_bytes(), prime,
                        3, 3).unwrap();
        let share_lists = shuffle_share_lists(share_lists, &hashed_pass, ShuffleOp::Shuffle);
        let share_lists = shuffle_share_lists(share_lists, &hashed_pass, ShuffleOp::ReverseShuffle);
        let recon_secret_vec = reconstruct_secrets_from_share_lists(share_lists, prime, 3).unwrap();
        let recon_secret = String::from_utf8(recon_secret_vec).unwrap();

        assert_eq!(secret, recon_secret);


    }



}
