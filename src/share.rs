use crate::geometry::*;
use num_bigint_dig::{BigInt, BigUint, RandBigInt};
use rand::rngs::{OsRng, StdRng};
use rand::SeedableRng;
use std::ops::Rem;



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
/// @_x_value_max_bits: This value is currently unused but will likely be implemented in the
///     future. It is safe for this value to be any number.
///
/// Return: This function will return Ok<Vec<Point>> upon success. 
pub fn create_shares_from_secret(secret: u8, prime: &BigInt, shares_required: usize, 
                        shares_to_create: usize, co_max_bits: usize, 
                        _x_value_max_bits: usize) -> Result<Vec<Point>, Error> {


    let mut shares: Vec<Point> = Vec::new();
    let mut share_poly = Polynomial::new();
    
    let mut rand = match OsRng::new() {
        Ok(rng) => StdRng::from_rng(rng).unwrap(),
        Err(_) => StdRng::from_rng(rand::thread_rng()).unwrap(),
    };

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
/// @secret: A slice of bytes to be used to create the vector of share vectors
/// ... For the rest of the arguments, see @create_shares_from_secret
pub fn create_share_lists_from_secrets(secret: &[u8], prime: &BigInt, shares_required: usize,
                                   shares_to_create: usize, co_max_bits: usize,
                                   _x_value_max_bits: usize) -> Result<Vec<Vec<Point>>, Error> {
    if secret.len() == 0 {
        return Err(Error::EmptySecretArray)
    }

    let mut list_of_share_lists: Vec<Vec<Point>> = Vec::new();

    for s in secret {
        match create_shares_from_secret(*s, 
                                           prime, 
                                           shares_required,
                                           shares_to_create,
                                           co_max_bits,
                                           _x_value_max_bits) {
            Ok(shares) => {
                // Now this list needs to be transposed:
                list_of_share_lists.push(shares);
            },
            Err(e) => {
                return Err(e);
            }
        }
    }

    Ok(list_of_share_lists)
}


/// This is a wrapper around @reconstruct_secret that iterates over each Vec of shares and
/// reconstructs their respective byte of the secret.
/// @share_lists: A Vec of Vecs, with each Vec containing the shares needed to reconstruct a byte
///     of the secret.
/// ... For the rest of the arguments, see @reconstruct_secret
pub fn reconstruct_secrets_from_share_lists(share_lists: Vec<Vec<Point>>, prime: &BigInt,
                                            shares_needed: usize) -> Result<Vec<u8>, Error> {
    let mut secrets: Vec<u8> = Vec::with_capacity(share_lists.len());

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
            Self::NotEnoughShares { given, required } => 
                write!(f, "Not enough shares to recreate secret: Given: {}; Required: {}", 
                       given, required),
            Self::InvalidMatrix { index_of_invalid_length_row } => 
                write!(f, "Row {} is not the same length as previous rows", index_of_invalid_length_row),
            Self::EmptySecretArray => write!(f, "Secret array should not be empty"),
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
    //use signal_hook::register;
    use rand::rngs::SmallRng;




    #[test]
    fn many_test() {

        let num_iters = 50;

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

        /* Was used to find an infinite loop, no longer needed
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
                bit_size_co, 
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
    fn large_data() {
        let mut rand = SmallRng::seed_from_u64(123);
        let secret = "Hello World and all who inhabit it";
        let shares_required = 5;
        let shares_to_create = 5;
        let co_max_bits = 64;
        let prime: BigInt = rand.gen_prime(128).into();
        let _x_value_max_bits = 128;

        let share_lists = create_share_lists_from_secrets(secret.as_bytes(), &prime, 
                          shares_required, shares_to_create, co_max_bits, _x_value_max_bits).unwrap();
        let share_lists = transpose_vec_matrix(&share_lists).unwrap();

        let recon_secret_vec = reconstruct_secrets_from_share_lists(
                transpose_vec_matrix(&share_lists).unwrap(), &prime, shares_required).unwrap();
        let recon_secret = String::from_utf8(recon_secret_vec).unwrap();
        assert_eq!(secret, &recon_secret[..])


    }

    


}





