use crate::basic_sharing::*;

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
        thread_rng().fill(secret.as_mut_slice());

        let mut shares =
            from_secrets_compressed(&secret, shares_required, shares_to_create, None).unwrap();

        shares.shuffle(&mut thread_rng());

        let selected_shares = &shares[0..shares_to_use_for_recon];

        let recon_secret = reconstruct_secrets_compressed(selected_shares).unwrap();
        assert_eq!(secret, recon_secret);
    }
}
