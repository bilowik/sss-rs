use sss_rs::basic_sharing::{from_secrets_no_points, reconstruct_secrets_no_points};
use rand::{Rng, thread_rng};

use criterion::{criterion_group, criterion_main, Criterion};

macro_rules! share_func {
    ($c:ident, $size:literal, $shares_required:literal, $shares_to_create:literal) => {{
        let bytes = (0..$size).map(|_| thread_rng().gen()).collect::<Vec<u8>>();
        $c.bench_function(&format!("basic_sharing_{}byte_{}_{}", $size, $shares_required, $shares_to_create), 
                          |b| b.iter(|| from_secrets_no_points(&bytes, $shares_required, $shares_to_create, None).unwrap()));

    }}
}
macro_rules! reconstruct_func {
    ($c:ident, $size:literal, $shares_required:literal, $shares_to_create:literal) => {{
        let bytes = (0..$size).map(|_| thread_rng().gen()).collect::<Vec<u8>>();
        let shares = from_secrets_no_points(&bytes, $shares_required, $shares_to_create, None).unwrap();
        $c.bench_function(&format!("basic_reconstruction_{}byte_{}_{}", $size, $shares_required, $shares_to_create), 
                          |b| b.iter(|| reconstruct_secrets_no_points(shares.clone())));

    }}
}

fn basic_sharing(c: &mut Criterion) {
    share_func!(c, 32, 2, 2);
    share_func!(c, 128, 2, 2);
    share_func!(c, 1024, 2, 2);
    share_func!(c, 8192, 2, 2);
    share_func!(c, 65536, 2, 2);

    reconstruct_func!(c, 32, 2, 2);
    reconstruct_func!(c, 128, 2, 2);
    reconstruct_func!(c, 1024, 2, 2);
    reconstruct_func!(c, 8192, 2, 2);
    reconstruct_func!(c, 65536, 2, 2);
}

criterion_group!(benches, basic_sharing);
criterion_main!(benches);
