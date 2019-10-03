
#[cfg(test)]
#[cfg(feature = "benchmarks")]
mod benchmarks {
    use sss_rs::*;
    use std::time::Instant;
    use std::path::Path;

    #[test]
    fn large_file_test() {
        env_logger::builder().is_test(true).try_init().unwrap();
        
        
        let dir = "./";
        let stem = "test.txt";
        let num_shares = 3u8;
        let secret = Secret::InFile(String::from("./test.txt"));
        let sharer = Sharer::builder(secret)
                            .shares_required(num_shares)
                            .shares_to_create(num_shares)
                            .build()
                            .unwrap();
        
        let start_sharing = Instant::now();
        sharer.share_to_files(dir, stem).unwrap();
        let mut recon = Secret::InFile(String::from("./test.txt.recon"));

        let elap_sharing = start_sharing.elapsed().as_millis();

        let start_recon = Instant::now();
        recon.reconstruct_from_files(dir, stem, num_shares).unwrap();
        let elap_recon = start_recon.elapsed().as_millis();

        for path in generate_share_file_paths(dir, stem, num_shares) {
            std::fs::remove_file(path).ok();
        }
        println!(
"Read Segment Size; {}
 Sharing time elapsed: {}
 Recon time elapsed: {}
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~",
 READ_SEGMENT_SIZE,
 elap_sharing,
 elap_recon);
    }


    #[test]
    fn stress_test() {
        // This test is mainly meant to try a vast number of different secrets 
        use rand::Rng;
        use rand::rngs::StdRng;
        use rand::FromEntropy;
        let dir = "./";
        let stem = ".stress_test_sharer";
        let mut rand = StdRng::from_entropy();

        for i in 0..100 {
            println!("RUN NUMBER: {}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~", i);
            let num_shares: u8 = rand.gen_range(2, 254);
            let secret_len: usize = rand.gen_range(1, 10000);
            let mut secret_buf = Vec::with_capacity(secret_len);
            unsafe { secret_buf.resize_with(secret_len, || 
                                            std::mem::MaybeUninit::uninit().assume_init()); }
            rand.fill(&mut secret_buf[..]);
            std::fs::write("./stress_test_original", &mut secret_buf[..]).unwrap();
            let sharer = Sharer::builder(Secret::InMemory(secret_buf.clone().to_vec()))
                                                .shares_required(num_shares)
                                                .shares_to_create(num_shares)
                                                .build()
                                                .unwrap();
            sharer.share_to_files(dir, stem).unwrap();
            let mut recon = Secret::point_at_file("./stress_test_recon");
            recon.reconstruct_from_files(dir, stem, num_shares).unwrap();
        }


        //cleanup
        for path in generate_share_file_paths(dir, stem, 254) {
            std::fs::remove_file(path).ok();
        }
    }


    pub fn generate_share_file_paths(dir: &str, stem: &str, num_files: u8) -> Vec<String> {
        let mut path_buf = Path::new(dir).to_path_buf();
        let mut generated_paths: Vec<String> = Vec::with_capacity(num_files as usize);

        for i in 0..num_files {
            path_buf.push(format!("{}.s{}", stem, i));
            (&mut generated_paths).push(String::from(path_buf.to_str().unwrap()));
            path_buf.pop();
        }

        generated_paths
    }

}
