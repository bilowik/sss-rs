use crate::basic_sharing::{from_secrets_compressed, reconstruct_secrets_compressed};
use std::error::Error;
use thiserror::Error;

use rand::{seq::SliceRandom, thread_rng, Rng};

const FUZZ_COUNT: usize = 100_000;
const SECRET_LEN_MIN: usize = 0;
const SECRET_LEN_MAX: usize = 10000;

#[test]
fn fuzz_basic_sharing() {
    for _ in 0..FUZZ_COUNT {
        let secret_len = thread_rng().gen_range(SECRET_LEN_MIN..SECRET_LEN_MAX);
        let shares_required = thread_rng().gen_range(2u8..=255);
        let shares_to_create = thread_rng().gen_range(shares_required..=255);

        let shares_to_use_for_recon =
            thread_rng().gen_range(shares_required..=shares_to_create) as usize;

        let mut secret: Vec<u8> = Vec::with_capacity(secret_len);
        unsafe {
            secret.set_len(secret_len);
        }
        thread_rng().fill(secret.as_mut_slice());

        let mut shares =
            from_secrets_compressed(&secret, shares_required, shares_to_create, None).unwrap();

        shares.shuffle(&mut thread_rng());

        let selected_shares = &shares[0..shares_to_use_for_recon];

        let recon_secret = reconstruct_secrets_compressed(selected_shares).unwrap();
        assert_eq!(secret, recon_secret);
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Error)]
pub struct FuzzTestInfo<E: Error> {
    pub secret: String,
    pub shares_to_create: u8,
    pub shares_required: u8,
    pub num_shares_attempted_for_recon: Option<u8>,
    pub recon_secret: Option<String>,

    #[source]
    pub source: Option<E>,
}

impl<E: Error + Clone + std::fmt::Debug + std::fmt::Display> FuzzTestInfo<E> {
    fn with_source(mut self, source: E) -> Self {
        self.source = Some(source);
        self
    }
}

#[test]
fn fuzz_all_combinations_max_shares() {
    let secret_len = 64;
    let mut secret = Vec::with_capacity(secret_len);
    unsafe {
        secret.set_len(secret_len);
    }
    thread_rng().fill(secret.as_mut_slice());

    let n = 255;
    let initial_required = 2;

    for shares_required in initial_required..n {
        let mut fuzz_test_info = FuzzTestInfo {
            secret: hex::encode(&secret),
            shares_to_create: 255,
            shares_required,
            num_shares_attempted_for_recon: None,
            recon_secret: None,
            source: None,
        };

        let shares = from_secrets_compressed(secret.as_slice(), shares_required, n, None)
            .map_err(|e| fuzz_test_info.clone().with_source(e))
            .unwrap();

        /*shares
            .into_iter()
            .combinations(shares_required as usize)
            .for_each(|shares| {
                match reconstruct_secrets_compressed(shares) {
                    Ok(recon_secret) => {

                    }
                }
                assert_eq!(&secret, &reconstruct_secrets_compressed(shares).unwrap())

            });

        Leaving this here so I never forget how horrific of a mistake this was.
        I mean it's only
        57896044618658097711785492504343953926634992332820282019728792003956564819711
        iterations, how long could that take? :)

        */

        for num_shares_for_recon in shares_required..n {
            fuzz_test_info.num_shares_attempted_for_recon = Some(num_shares_for_recon);
            let recon_secret =
                reconstruct_secrets_compressed(&shares[0..(num_shares_for_recon as usize)])
                    .map_err(|e| fuzz_test_info.clone().with_source(e))
                    .unwrap();
            fuzz_test_info.recon_secret = Some(hex::encode(&recon_secret));

            if &recon_secret != &secret {
                panic!("{:?}", fuzz_test_info);
            }
        }
    }
}
