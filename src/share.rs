use crate::geometry::*;
use num_bigint_dig::{BigInt, BigUint, RandBigInt};
use rand::rngs::{OsRng, StdRng};
use rand::SeedableRng;
use std::ops::Rem;




pub fn create_shares_from_secret(secret: u8, prime: &BigInt, shares_required: usize, 
                        shares_to_create: usize, co_max_bits: usize, 
                        _x_value_max_bits: usize) -> Result<Vec<Point>, ()> {


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

pub fn reconstruct_secret(shares: Vec<Point>, prime: &BigInt, 
                          shares_needed: usize) -> Result<u8, ()> {
    match Polynomial::from_points(shares, shares_needed - 1) {
        Ok(poly) => {
            Ok(poly.get_term(0)
                        .get_co()
                        .rem(prime)
                        .get_numerator()
                        .to_bytes_le().1[0])
        }
        Err(_) => Err(()),
    }
}


pub fn create_share_lists_from_secrets(secret: &[u8], prime: &BigInt, shares_required: usize,
                                   shares_to_create: usize, co_max_bits: usize,
                                   _x_value_max_bits: usize) -> Result<Vec<Vec<Point>>, ()> {

    


    let mut list_of_share_lists: Vec<Vec<Point>> = Vec::new();

    for _ in 0..secret.len() {
        list_of_share_lists.push(Vec::with_capacity(shares_to_create));
    }

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
            Err(_) => {
                return Err(());
            }
        }
    }

    Ok(list_of_share_lists)
}



/// The share lists should be in this format since this is how they would be distributed:
/// Each Vec in Vec<Vec<Point>> should be: share1byte1, share1byte2, share1byte3 and so on.
/// The first index is the share, the second being the byte of the share.
/// This is also how they are outputted so it can easily be sent back through and decrypted without
/// modification.
pub fn reconstruct_secrets_from_share_lists(share_lists: Vec<Vec<Point>>, prime: &BigInt,
                                            shares_needed: usize) -> Result<Vec<u8>, ()> {
    let mut secrets: Vec<u8> = Vec::with_capacity(share_lists.len());

    for point_list in share_lists {
        match reconstruct_secret(point_list, prime, shares_needed) {
            Ok(secret) => {
                secrets.push(secret);
            },
            Err(_) => {
                return Err(());
            }
        }
    }
    Ok(secrets)
}



/// Returns the "matrix" as is if the rows don't have an equal number of columns
pub fn transpose_vec_matrix<T: Clone>(matrix: &Vec<Vec<T>>) -> Result<Vec<Vec<T>>, ()> {

    for i in 1..matrix.len() {
        if matrix[i - 1].len() != matrix[i].len() {
            return Err(());
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


    /*
    #[test]
    fn large_data() {
        let rand = SmallRng::seed_from_u64(123);
        let secret = "Hello World";
        let shares_required = 3;
        let shares_to_create = 3;
        let co_max_bits = 64;
        let prime = rand.gen_prime(128);
        let _x_value_max_bits = 128;

        let share_lists = create_share_lists_from_secrets(secret.as_bytes(), prime.into(), 
                          shares_required, shares_to_create, co_max_bits, _x_value_max_bits);
        let recon_secret = 


    }
    */


}




