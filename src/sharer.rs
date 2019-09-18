/*use crate::raw_share::*;
use crate::geometry::Point;
use rand::{Rng, FromEntropy};
use rand::rngs::StdRng;
use num_bigint_dig::{BigInt, BigUint, RandPrime};
use std::rc::Rc;
use std::io::{Read, Write};


pub enum Share {


#[derive(Debug)]
pub struct Sharer {
    shares: Vec<Share>,
    secret: Rc<Vec<u8>>,
    prime: BigInt,
    shares_required: usize,
}

#[derive(Debug)]
pub struct SharerBuilder {
    secret: Rc<Vec<u8>>, // The secret to be shared (Wrapped in an Rc to avoid having to make expensive
                         // copies)
    coefficient_bits: usize, // The number of bits the random coefficients of the polynomial will have.
    shares_required: usize, // The number of shares needed to reconstruct the secret
    shares_to_create: usize, // The number of shares to generate
    keep_x_values: bool, // Determines whether the X-values are kept or removed
    prime: BigInt, // The prime number use to bring the underlying share polynomial into a finite field
}




impl Sharer {
    pub fn share<T: Write>(&self, mut dest: T, share_num: usize) 
        -> Result<(), Box<dyn std::error::Error>> {
    }


}


impl SharerBuilder {
    pub fn build(&mut self) -> Result<Sharer, Box<dyn std::error::Error>> {

            
        let shares = create_share_lists_from_secrets(   self.secret.as_slice(),
                                                        &self.prime,
                                                        self.shares_required,
                                                        self.shares_to_create,
                                                        self.coefficient_bits)?;
        Ok(Sharer {
            shares: shares,
            secret: self.secret.clone(),
            prime: self.prime.clone(),
            shares_required: self.shares_required,
        })
    
    }

    /// Use a specific prime for the generation of the shares. The given prime is checked with an
    /// astronomically low chance for being incorrect. It's recommended to use the default prime or
    /// randomly generate one with rand_prime
    fn prime(mut self, prime: BigUint) -> Result<Self, Box<dyn std::error::Error>> {
        if num_bigint_dig::prime::probably_prime(&prime, 25) {
            self.prime = prime.into();
            Ok(self)
        }
        else {
            Err(Box::new(Error::NotPrime(prime)))
        }
    }


    /// Uses the given RNG to seed the RNG that generates the prime number. The prime number will
    /// be generated with prime_bits number of bits. If None is specified for the RNG, then StdRng
    /// is used and seeded from entropy.
    fn rand_prime<T: Rng>(mut self, rng: Option<T>, prime_bits: usize) -> Self {
        self.prime = match rng {
            Some(mut rng) => rng.gen_prime(prime_bits).into(),
            None => StdRng::from_entropy().gen_prime(prime_bits).into(),
        };
        self
    }

    fn coefficient_bits(mut self, coefficient_bits: usize) -> Self {
        self.coefficient_bits = coefficient_bits;
        self
    }

    fn shares_required(mut self, shares_required: usize) -> Self {
        self.shares_required = shares_required;
        self
    }

    fn shares_to_create(mut self, shares_to_create: usize) -> Self {
        self.shares_to_create = shares_to_create;
        self
    }

}


impl Default for SharerBuilder {
    fn default() -> Self {
        Self {
            secret: dbg!(Rc::new(Vec::with_capacity(0))),
            coefficient_bits: 32,
            shares_required: 3,
            shares_to_create: 3,
            prime: BigInt::from(2147483647)
        }

    }

}


#[derive(Debug, Clone)]
pub enum Error {
    NotPrime(BigUint),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::NotPrime(not_prime) => {
                write!(f, "{} is not a prime number, which is required for SSS", not_prime)
            }
        }
    }
}

impl std::error::Error for Error {}


*/
