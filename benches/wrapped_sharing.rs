use rand::{thread_rng, Rng};
use sss_rs::wrapped_sharing::{Reconstructor, Sharer};
use std::io::{Cursor, Seek};

#[cfg(wrapped_sharing_bench_use_disk_io)]
use tempfile::tempfile;

use criterion::{criterion_group, criterion_main, Criterion};

#[cfg(wrapped_sharing_bench_use_disk_io)]
fn get_writable() -> File {
    tempfile().unwrap()
}

#[cfg(not(wrapped_sharing_bench_use_disk_io))]
fn get_writable() -> Cursor<Vec<u8>> {
    Cursor::new(Vec::new())
}

macro_rules! share_func {
    ($c:ident, $size:expr, $chunk_size:expr, $shares_required:literal, $shares_to_create:literal) => {{
        let mut bytes = Vec::with_capacity($size);
        unsafe { bytes.set_len($size) }; // For quicker setup for tests.
        thread_rng().fill(bytes.as_mut_slice());

        let mut dest1 = get_writable();
        let mut dest2 = get_writable();
        let byte_chunks = bytes.chunks($chunk_size).collect::<Vec<&[u8]>>();
        $c.bench_function(
            &format!(
                "wrapped_sharing_{}byte_{}chunksize_{}_{}",
                $size, $chunk_size, $shares_required, $shares_to_create
            ),
            |b| {
                b.iter(|| {
                    let mut sharer = Sharer::builder()
                        .with_shares_required(2)
                        .with_output(&mut dest1)
                        .with_output(&mut dest2)
                        .with_verify(true)
                        .build()
                        .unwrap();

                    for secret in byte_chunks.iter() {
                        sharer.update(secret).unwrap();
                    }
                    sharer.finalize().unwrap();
                });
                dest1.rewind().unwrap();
                dest2.rewind().unwrap();
            },
        );
    }};
}
macro_rules! reconstruct_func {
    ($c:ident, $size:expr, $chunk_size:expr, $shares_required:literal, $shares_to_create:literal) => {{
        let mut bytes = Vec::with_capacity($size);
        unsafe { bytes.set_len($size) }; // For quicker setup for tests.
        thread_rng().fill(bytes.as_mut_slice());
        let mut dest1 = Cursor::new(Vec::new());
        let mut dest2 = Cursor::new(Vec::new());
        let byte_chunks = bytes.chunks($chunk_size).collect::<Vec<&[u8]>>();

        let mut recon_dest = get_writable();

        let mut sharer = Sharer::builder()
            .with_shares_required(2)
            .with_output(&mut dest1)
            .with_output(&mut dest2)
            .with_verify(true)
            .build()
            .unwrap();

        for secret in byte_chunks.iter() {
            sharer.update(secret).unwrap();
        }
        sharer.finalize().unwrap();

        $c.bench_function(
            &format!(
                "wrapped_reconstruction_{}byte_{}chunksize_{}_{}",
                $size, $chunk_size, $shares_required, $shares_to_create
            ),
            |b| {
                b.iter(|| {
                    let mut reconstructor = Reconstructor::new(&mut recon_dest, true);

                    for (chunk1, chunk2) in dest1
                        .get_ref()
                        .chunks($chunk_size)
                        .zip(dest2.get_ref().chunks($chunk_size))
                    {
                        reconstructor.update(&[chunk1, chunk2]).unwrap();
                    }
                    reconstructor.finalize().unwrap();
                });
                recon_dest.rewind().unwrap();
            },
        );
    }};
}

fn wrapped_sharing(c: &mut Criterion) {
    share_func!(c, 1 << 18, 1 << 13, 2, 2);
    share_func!(c, 1 << 22, 1 << 13, 2, 2);

    reconstruct_func!(c, 1 << 18, 1 << 13, 2, 2);
    reconstruct_func!(c, 1 << 22, 1 << 13, 2, 2);
}

criterion_group!(benches, wrapped_sharing);
criterion_main!(benches);
