//! Padding must not be recognisable: Server2 sees every block Server1 sends, so a filler value
//! or dummy block that occurs more than once would tell it apart from real data.

use std::{collections::HashSet, sync::Arc};

use myco::{
    constants::{BLOCK_SIZE, INNER_BLOCK_SIZE, LAMBDA_BYTES, NOTIFICATION_BUCKET_SIZE_BYTES, Q, Z, Z_M},
    dtypes::Key,
    network::server2::LocalServer2Access,
    server1::Server1,
    server2::Server2,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tokio::sync::RwLock;

#[tokio::test]
async fn no_padding_value_occurs_twice() {
    let num_clients = 16;
    let s2 = Arc::new(RwLock::new(Server2::new(num_clients)));
    let mut s1 = Server1::new(Box::new(LocalServer2Access { server: s2.clone() }), num_clients);
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);

    s1.batch_init().unwrap();
    for client in 0..num_clients {
        let mut ct = vec![0u8; INNER_BLOCK_SIZE];
        let mut ct_ntf = vec![0u8; LAMBDA_BYTES];
        rng.fill_bytes(&mut ct);
        rng.fill_bytes(&mut ct_ntf);
        s1.queue_write(ct, ct_ntf, vec![client as u8; 16], vec![client as u8; 16], Key::random(&mut rng), format!("c{}", client).into_bytes())
            .unwrap();
    }
    let table_index = s2.read().await.latest_notif_table_idx;
    s1.batch_write().unwrap();

    let s2 = s2.read().await;

    // Notification table: every bucket is full and no 16-byte value repeats anywhere.
    let table = &s2.notification_tables[table_index];
    assert_eq!(table.len(), Q * num_clients * NOTIFICATION_BUCKET_SIZE_BYTES);
    assert_eq!(NOTIFICATION_BUCKET_SIZE_BYTES, Z_M * LAMBDA_BYTES);
    let values: HashSet<&[u8]> = table.chunks(LAMBDA_BYTES).collect();
    assert_eq!(values.len(), Q * num_clients * Z_M, "a notification value occurs more than once");

    // Tree: every written bucket holds Z blocks and no block repeats anywhere.
    let mut blocks: HashSet<Vec<u8>> = HashSet::new();
    let mut written = 0;
    for bucket in s2.tree.value.iter().flatten().filter(|bucket| !bucket.is_empty()) {
        let bytes: Vec<u8> = bucket.iter().flat_map(|block| block.0.iter().copied()).collect();
        assert_eq!(bytes.len(), Z * BLOCK_SIZE);
        for block in bytes.chunks(BLOCK_SIZE) {
            assert!(blocks.insert(block.to_vec()), "a block occurs more than once");
        }
        written += 1;
    }
    assert_eq!(written, s1.pathset().len());
}
