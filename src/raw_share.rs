use crate::geometry::*;
use num_bigint_dig::{BigInt, BigUint, RandBigInt};
use rand::rngs::{OsRng, StdRng};
use rand::{SeedableRng, Rng, RngCore, FromEntropy};
use std::ops::Rem;
use crypto::sha3::Sha3;
use crypto::digest::Digest;
use rand::seq::SliceRandom;
use rand_chacha::ChaChaRng;


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
pub fn create_shares_from_secret(secret: u8, prime: &BigInt, shares_required: usize, 
                        shares_to_create: usize, co_max_bits: usize) -> Result<Vec<Point>, Error> {


    let mut shares: Vec<Point> = Vec::new();
    let mut share_poly = Polynomial::new();
    
    let mut rand = StdRng::from_entropy();

    share_poly.set_term(Term::new(secret, 0));

    for i in 1..shares_required {
        let curr_co: BigUint = rand.gen_biguint(co_max_bits);
        share_poly.set_term(Term::new(curr_co, i as usize));
    }


    for i in 1..=shares_to_create {
        let curr_x = Fraction::new(i, 1);
        let curr_y: Fraction = share_poly.get_y_value(&curr_x) % prime;
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
pub fn reconstruct_secret(shares: Vec<Point>, prime: &BigInt, 
                          shares_needed: usize) -> Result<u8, Error> {
    match Polynomial::from_points(&shares, shares_needed - 1) {
        Ok(poly) => {
            Ok(poly.get_term(0)
                        .get_co()
                        .rem(prime)
                        .get_numerator()
                        .to_bytes_le().1[0])
        }
        Err(_) => Err(Error::NotEnoughShares { given: shares.len(), required: shares_needed }),
    }
}


/// This is a wrapper around @create_share_from_secret that loops through the @secret slice and
/// returns a vector of vectors, with each vector being all the shares for a single byte of the
/// secret.
/// The format this returns the secrets in is:
///     share1byte1, share1byte2, share1byte3, ..., share1byte<share_lists.len()> 
///     share2byte1, share2byte2, share2byte3, ..., share2byte<share_lists.len()>
/// since that is how they would be distributed.
/// @secret: A slice of bytes to be used to create the vector of share vectors
/// ... For the rest of the arguments, see @create_shares_from_secret
pub fn create_share_lists_from_secrets(secret: &[u8], prime: &BigInt, shares_required: usize,
                                   shares_to_create: usize, co_max_bits: usize,
                                   ) -> Result<Vec<Vec<Point>>, Error> {
    if secret.len() == 0 {
        return Err(Error::EmptySecretArray)
    }

    let mut list_of_share_lists: Vec<Vec<Point>> = Vec::new();

    for s in secret {
        match create_shares_from_secret(*s, 
                                           prime, 
                                           shares_required,
                                           shares_to_create,
                                           co_max_bits) {
            Ok(shares) => {
                // Now this list needs to be transposed:
                list_of_share_lists.push(shares);
            },
            Err(e) => {
                return Err(e);
            }
        }
    }

    Ok(transpose_vec_matrix(&list_of_share_lists).unwrap())
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
pub fn reconstruct_secrets_from_share_lists(share_lists: Vec<Vec<Point>>, prime: &BigInt,
                                            shares_needed: usize) -> Result<Vec<u8>, Error> {
    let mut secrets: Vec<u8> = Vec::with_capacity(share_lists.len());
    let share_lists = transpose_vec_matrix(&share_lists)?;
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
pub fn transpose_vec_matrix<T: Clone>(matrix: &Vec<Vec<T>>) -> Result<Vec<Vec<T>>, Error> {

    for i in 1..matrix.len() {
        if matrix[i - 1].len() != matrix[i].len() {
            return Err(Error::InvalidMatrix { index_of_invalid_length_row: i } );
        }
    }

    let mut transpose: Vec<Vec<T>> = Vec::new();

    for _ in 0..matrix[0].len() {
        transpose.push(Vec::new());
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
    use num_bigint_dig::RandPrime;
    use rand::SeedableRng;
    use rand::Rng;
    use super::*;
    use rand::rngs::SmallRng;

    #[test]
    fn many_test() {

        let num_iters = 10;

        let mut rand = SmallRng::seed_from_u64(123u64);

        for _ in 0..num_iters {
            let secret: u8 = rand.gen_range(1, 256) as u8;
            let shares_required = rand.gen_range(2, 10);
            let shares_to_create = shares_required + rand.gen_range(0, 6);
            let bit_size_co: usize = rand.gen_range(32, 65);
            let prime_bits: usize = rand.gen_range(bit_size_co + 128, 257);
            let mut prime: BigUint = rand.gen_prime(prime_bits);
            while prime < BigUint::from(secret) {
                prime = rand.gen_prime(prime_bits);
            }

            basic_single_value(secret, prime, bit_size_co, shares_to_create, shares_required);
        }

    }


    fn basic_single_value(secret: u8, prime: BigUint, bit_size_co: usize, 
                          shares_to_create: usize, shares_required: usize) {

        /* Was used to find an infinite loop, no longer needed, but keeping for future reference
        unsafe {
            register(signal_hook::SIGQUIT, || println!("{:?}", Backtrace::new()));
        }
        */
        
        assert!(num_bigint_dig::prime::probably_prime(&prime, 10));
        let prime: BigInt = prime.into();



        let shares = create_shares_from_secret(
                secret, 
                &prime.clone().into(), 
                shares_required, 
                shares_to_create, 
                bit_size_co)
            .unwrap();

        let secret_decrypted = reconstruct_secret(shares, &prime, shares_required).unwrap();
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

        assert_eq!(transpose_vec_matrix(&matrix).unwrap(), matrix1);
        assert_eq!(transpose_vec_matrix(&matrix2).unwrap(), matrix3);
    }


    
    #[test]
    fn large_data_and_benchmark() {
        use std::time::Instant;

        let mut rand = SmallRng::seed_from_u64(123);
        let secret = 
            "According to all known laws of aviation, 
            there is no way a bee should be able to fly.
            Its wings are too small to get its fat little body off the ground.
            The bee, of course, flies anyway
            because bees don't care what humans think is impossible.";
        let shares_required = 5;
        let shares_to_create = 5;
        let co_max_bits = 64;
        let prime: BigInt = rand.gen_prime(128).into();
        
        println!("Prime: {}", prime);

    
        let now = Instant::now();

        let share_lists = create_share_lists_from_secrets(secret.as_bytes(), &prime, 
                          shares_required, shares_to_create, co_max_bits).unwrap();

        let recon_secret_vec = reconstruct_secrets_from_share_lists(
                share_lists, &prime, shares_required).unwrap();
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

        let mut rand = StdRng::seed_from_u64(123);
        let prime: BigInt = rand.gen_prime(64).into();
        let share_lists = create_share_lists_from_secrets(secret.as_bytes(), &prime,
                        3, 3, 64).unwrap();
        let share_lists = shuffle_share_lists(share_lists, &hashed_pass, ShuffleOp::Shuffle);
        let share_lists = shuffle_share_lists(share_lists, &hashed_pass, ShuffleOp::ReverseShuffle);
        let recon_secret_vec = reconstruct_secrets_from_share_lists(share_lists, &prime, 3).unwrap();
        let recon_secret = String::from_utf8(recon_secret_vec).unwrap();

        assert_eq!(secret, recon_secret);


    }



}
