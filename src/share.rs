use crate::geometry::*;
use num_bigint_dig::{BigInt, BigUint, RandBigInt};
use rand::rngs::{OsRng, StdRng};
use rand::Rng;
use rand::distributions::Distribution;
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

    for s in secret {
        match create_shares_from_secret(*s, 
                                           prime, 
                                           shares_required,
                                           shares_to_create,
                                           co_max_bits,
                                           _x_value_max_bits) {
            Ok(shares) => {
                list_of_share_lists.push(shares);
            },
            Err(_) => {
                return Err(());
            }
        }
    }

    Ok(list_of_share_lists)
}


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








#[cfg(test)]
mod tests {
    use num_bigint_dig::RandPrime;
    use num_bigint_dig::RandBigInt;
    use rand::SeedableRng;
    use rand::Rng;
    use super::*;
    use signal_hook::register;
    use backtrace::Backtrace;




    #[test]
    fn many_test() {
        use num_traits::Pow;

        let num_iters = 50;

        let mut rand = rand::rngs::OsRng::new().unwrap();

        for i in 0..num_iters {
            let secret: u8 = rand.gen_range(1, 255);
            let shares_required = rand.gen_range(2, 10);
            let shares_to_create = shares_required + rand.gen_range(0, 5);
            let bit_size_co: usize = rand.gen_range(64, 128);
            let prime_bits: usize = rand.gen_range(bit_size_co + 128, 512);
            let mut prime: BigUint = rand.gen_prime(prime_bits);
            println!("Prime: {}", prime); 
            while prime < BigUint::from(secret) {
                prime = rand.gen_prime(prime_bits);
            }

            basic_single_value(secret, prime, bit_size_co, shares_to_create, shares_required);
        }

    }


    fn basic_single_value(secret: u8, prime: BigUint, bit_size_co: usize, 
                          shares_to_create: usize, shares_required: usize) {

        unsafe {
            register(signal_hook::SIGQUIT, || println!("{:?}", Backtrace::new()));
        }
        
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


}




