//! A client finds its message when many clients write in the same epoch, both when reads
//! return the whole path and, with the `short-reads` feature, when they skip the top levels.

use std::sync::Arc;

use myco::{
    client::Client,
    constants::{D, INNER_BLOCK_SIZE, LAMBDA_BYTES, MIN_PATHS_PER_BUCKET},
    dtypes::Key,
    network::{server1::LocalServer1Access, server2::LocalServer2Access},
    server1::Server1,
    server2::Server2,
    utils::read_skipped_levels,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tokio::sync::RwLock;

#[test]
fn skipped_levels_follow_the_number_of_clients() {
    if cfg!(feature = "short-reads") {
        assert_eq!(read_skipped_levels(1), 0);
        assert_eq!(read_skipped_levels(2 * MIN_PATHS_PER_BUCKET - 1), 0);
        assert_eq!(read_skipped_levels(2 * MIN_PATHS_PER_BUCKET), 1);
        assert_eq!(read_skipped_levels(8 * MIN_PATHS_PER_BUCKET), 3);
        assert_eq!(read_skipped_levels(usize::MAX), D);
    } else {
        assert_eq!(read_skipped_levels(8 * MIN_PATHS_PER_BUCKET), 0);
    }
}

#[tokio::test]
async fn one_client_among_many_reads_its_message() {
    let num_clients = 8 * MIN_PATHS_PER_BUCKET;
    let skipped = read_skipped_levels(num_clients);

    let s2 = Arc::new(RwLock::new(Server2::new(num_clients)));
    let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
    let s1 = Arc::new(RwLock::new(Server1::new(s2_access.clone(), num_clients)));
    let s1_access = Box::new(LocalServer1Access { server: s1.clone() });

    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    let mut client = Client::new("Client".to_string(), s1_access, s2_access, num_clients);
    client.setup(vec![Key::random(&mut rng)], vec!["Client".to_string()]).unwrap();

    for epoch in 0..6u8 {
        s1.write().await.batch_init().unwrap();

        let message = vec![epoch + 1; 16];
        client.write(&message, "Client").unwrap();
        // Every other client writes a block of random bytes to a random place.
        for other in 1..num_clients {
            let mut ct = vec![0u8; INNER_BLOCK_SIZE];
            let mut ct_ntf = vec![0u8; LAMBDA_BYTES];
            let mut f = vec![0u8; 16];
            let mut f_ntf = vec![0u8; 16];
            rng.fill_bytes(&mut ct);
            rng.fill_bytes(&mut ct_ntf);
            rng.fill_bytes(&mut f);
            rng.fill_bytes(&mut f_ntf);
            s1.write()
                .await
                .queue_write(ct, ct_ntf, f, f_ntf, Key::random(&mut rng), format!("Other_{}", other).into_bytes())
                .unwrap();
        }

        s1.write().await.batch_write().unwrap();

        assert_eq!(client.read(Some(1)).unwrap(), message, "epoch {}", epoch);

        // A read returns the path from the first level readers download down to the leaf.
        let path: Vec<u8> = (0..LAMBDA_BYTES).map(|_| rng.next_u32() as u8).collect();
        assert_eq!(s2.read().await.read(path).unwrap().len(), D + 1 - skipped);
        // No message is held above that level.
        assert_eq!(s1.read().await.held_by_depth()[..skipped].iter().sum::<usize>(), 0);
    }
}
