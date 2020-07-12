use crate::geometry::*;
use rand::{Rng, RngCore, SeedableRng};
use rand::rngs::StdRng;



/// This function is similar except that a custom RNG can be used to produce the coefficients.
///
/// See [create_shares_from_secret] for documentation.
///
/// NOTE: USE WITH CAUTION, static seeding can lead to predictable sharing and loss of unconditional
/// security.
pub fn create_shares_from_secret_custom_rng(secret: u8, shares_required: u8, shares_to_create: u8, 
                                            rand: &mut Box<dyn RngCore>) -> Result<Vec<(u8, u8)>, Error> {

    if shares_required > shares_to_create {
        return Err(Error::UnreconstructableSecret(shares_to_create, shares_required));
    }
    if shares_to_create < 2 {
        return Err(Error::InvalidNumberOfShares(shares_to_create));
    }

    let mut shares: Vec<(u8, u8)> = Vec::new();
    let mut share_poly = GaloisPolynomial::new();
    

    share_poly.set_coeff(Coeff(secret), 0);

    for i in 1..shares_required {
        let curr_co: u8 = rand.gen_range(2, 255);
        // Limiting the coefficient size to i16 lowers the risk of overflow when calculating y
        // values
        
        share_poly.set_coeff(Coeff(curr_co), i as usize);
    }
    

    for i in 1..=shares_to_create {
        let curr_x = i as u8;
        let curr_y = share_poly.get_y_value(curr_x);
        shares.push((curr_x, curr_y));
    }
    Ok(shares)
}


/// Creates a vector of points that serve as the list of shares for a given byte of data. 
///
/// **secret:** The secret value that is to be split into shares
///
/// **shares_required:** The number of shares required to recreate the secret
///
/// **shares_to_create:** The number of shares to create, so any number 'x' shares from the total 'y'
/// shares are enough to recreate the secret. If < shares_required, it's automatically bumped up.
pub fn create_shares_from_secret(secret: u8, shares_required: u8, 
                        shares_to_create: u8) -> Result<Vec<(u8, u8)>, Error> {
    create_shares_from_secret_custom_rng(secret, shares_required, shares_to_create, 
                                &mut (Box::new(StdRng::from_entropy()) as Box<dyn RngCore>))
}


/// Reconstructs a secret from a given Vector of shares (points) and returns that secret. 
///
/// No guarantees are made that the shares are valid together and that the secret is valid. 
/// If there are enough shares, a secret will be generated.
///
/// **shares:** The vector of shares that are used to regenerate the polynomial and finding the
///     secret. @shares.len() must be >= @shares_needed, else this will return an error.
///
/// This will return an error if **shares.len() < shares_needed**.
pub fn reconstruct_secret(shares: Vec<(u8, u8)>) -> u8 {
    GaloisPolynomial::get_y_intercept_from_points(shares.as_slice())
}



/// This function is similar except that a custom RNG can be used to produce the coefficients.
///
/// See [create_shares_from_secret] for documentation
///
/// NOTE: USE WITH CAUTION, static seeding can lead to predictable sharing and loss of unconditional
/// security.
pub fn create_share_lists_from_secrets_custom_rng(secret: &[u8], shares_required: u8,
                                   shares_to_create: u8, rand: &mut Box<dyn RngCore>
                                   ) -> Result<Vec<Vec<(u8, u8)>>, Error> {
    if secret.len() == 0 {
        return Err(Error::EmptySecretArray);
    }

    let mut list_of_share_lists: Vec<Vec<(u8, u8)>> = Vec::with_capacity(secret.len());
    for s in secret {
        match create_shares_from_secret_custom_rng(*s, 
                                           shares_required,
                                           shares_to_create,
                                           rand) {
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



/// This is a wrapper around [create_shares_from_secret]
/// that loops through the *secret* slice and secret.
///
/// The format this returns the secrets in is, since this is how they would be 
/// distributed:
///
///     share1byte1, share1byte2, share1byte3, ..., share1byte<share_lists.len()> 
///
///     share2byte1, share2byte2, share2byte3, ..., share2byte<share_lists.len()>
///
/// **secret:** A slice of bytes to be used to create the vector of share vectors
///
/// For the rest of the arguments, see [create_shares_from_secret]
pub fn create_share_lists_from_secrets(secret: &[u8], shares_required: u8,
                                   shares_to_create: u8
                                   ) -> Result<Vec<Vec<(u8, u8)>>, Error> {
    create_share_lists_from_secrets_custom_rng(secret, shares_required, shares_to_create,
                                            &mut (Box::new(StdRng::from_entropy()) as Box<dyn RngCore>))
}


/// This is a wrapper around @reconstruct_secret that iterates over each Vec of shares and
/// reconstructs their respective byte of the secret.
/// 
/// It expects the shares to be in this format since this is how they are distributed.
/// In other words, the share lists generated from
/// 
///     share1byte1, share1byte2, share1byte3, ..., share1byte<share_lists.len()> 
///
///     share2byte1, share2byte2, share2byte3, ..., share2byte<share_lists.len()>
///
/// **share_lists:** A Vec of Vecs, with each Vec containing the shares needed to reconstruct a byte
///     of the secret.
///
/// ... For the rest of the arguments, see @reconstruct_secret
pub fn reconstruct_secrets_from_share_lists(share_lists: Vec<Vec<(u8, u8)>>) -> Result<Vec<u8>, Error> {
    let mut secrets: Vec<u8> = Vec::with_capacity(share_lists.len());
    let share_lists = transpose_vec_matrix(share_lists)?;
    for point_list in share_lists {
        secrets.push(reconstruct_secret(point_list)); 
    }
    Ok(secrets)
}


/// Transposes a Vec of Vecs if it is a valid matrix. If it is not an error is returned.
/// 
/// **matrix:** The matrix to be transposed, must be a valid matrix else an error is returned.
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
    NotEnoughShares { given: u8, required: u8 },
    InvalidMatrix { index_of_invalid_length_row: usize },
    InvalidNumberOfShares(u8),
    UnreconstructableSecret(u8, u8),
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
            Error::InvalidNumberOfShares(num) => 
                write!(f, "Need to generate at least 2 shares. Requested: {}", num),
            Error::UnreconstructableSecret(to_create, required) => 
                write!(f, "Can't create less shares than required to reconstruct. Create: {}, Req: {}",
                       to_create, required),
        }
    }
}

impl std::error::Error for Error {}


#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::Rng;
    use super::*;
    use rand::rngs::StdRng;

    #[test]
    fn many_test() {

        let num_iters = 10;

        let mut rand = StdRng::seed_from_u64(123u64);

        for _ in 0..num_iters {
            let secret: u8 = rand.gen_range(1, 256) as u8;
            let shares_required: u8 = rand.gen_range(2, 10);
            let shares_to_create: u8 = shares_required + rand.gen_range(0, 6);

            basic_single_value(secret, shares_to_create, shares_required);
        }

    }


    fn basic_single_value(secret: u8, shares_to_create: u8, shares_required: u8) {

        /* Was used to find an infinite loop, no longer needed, but keeping for future reference
        unsafe {
            register(signal_hook::SIGQUIT, || println!("{:?}", Backtrace::new()));
        }
        */
        
        let shares = create_shares_from_secret(
                secret, 
                shares_required, 
                shares_to_create)
            .unwrap();

        let secret_decrypted = reconstruct_secret(shares);
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

    
        let now = Instant::now();

        let share_lists = create_share_lists_from_secrets(secret.as_bytes(), 
                          shares_required, shares_to_create).unwrap();

        let recon_secret_vec = reconstruct_secrets_from_share_lists(share_lists).unwrap();
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

        let share_lists = create_share_lists_from_secrets(secret.as_bytes(), 3, 3).unwrap();
        let share_lists = shuffle_share_lists(share_lists, &hashed_pass, ShuffleOp::Shuffle);
        let share_lists = shuffle_share_lists(share_lists, &hashed_pass, ShuffleOp::ReverseShuffle);
        let recon_secret_vec = reconstruct_secrets_from_share_lists(share_lists).unwrap();
        let recon_secret = String::from_utf8(recon_secret_vec).unwrap();

        assert_eq!(secret, recon_secret);


    }



}
