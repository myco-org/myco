//! Server2 stores each tree bucket as one contiguous block and each notification table as
//! one flat buffer. These tests check that what it serves is byte-for-byte what it was sent.

use myco::constants::{BLOCK_SIZE, LAMBDA_BYTES, NOTIFICATION_BUCKET_SIZE_BYTES, Q, Z, Z_M};
use myco::dtypes::{Block, Bucket};
use myco::proto::myco as proto;
use myco::server2::Server2;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;

fn random_bytes(len: usize, rng: &mut ChaCha20Rng) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn flatten(bucket: &Bucket) -> Vec<u8> {
    bucket.iter().flat_map(|block| block.0.clone()).collect()
}

#[test]
fn stored_tree_bucket_serves_the_same_wire_bytes() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let wire = proto::Bucket { data: random_bytes(Z * BLOCK_SIZE, &mut rng), signature: random_bytes(64, &mut rng) };

    let per_block: Bucket = wire.clone().into();
    let stored = wire.clone().into_stored();

    assert_eq!(per_block.len(), Z);
    assert_eq!(stored.len(), 1);
    assert_eq!(proto::Bucket::from(&stored), proto::Bucket::from(&per_block));
    assert_eq!(proto::Bucket::from(&stored), wire);
}

#[test]
fn notification_tables_serve_what_was_written() {
    let num_clients = 3;
    let num_buckets = num_clients * Q;
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let raw = random_bytes(num_buckets * NOTIFICATION_BUCKET_SIZE_BYTES, &mut rng);
    let buckets: Vec<Bucket> = raw
        .chunks(NOTIFICATION_BUCKET_SIZE_BYTES)
        .map(|bucket| Bucket(bucket.chunks(LAMBDA_BYTES).map(|block| Block::new(block.to_vec())).collect(), None))
        .collect();

    // The same table written as whole buckets and as two raw chunks.
    let mut from_buckets = Server2::new(num_clients);
    from_buckets.write_notifs(buckets.clone());
    let mut from_chunks = Server2::new(num_clients);
    let split = (num_buckets / 2) * NOTIFICATION_BUCKET_SIZE_BYTES;
    from_chunks.write_notifs_chunk(num_buckets / 2, &raw[split..]);
    from_chunks.write_notifs_chunk(0, &raw[..split]);

    let ls: Vec<Vec<u8>> = (0..500).map(|_| random_bytes(8, &mut rng)).collect();
    let read = |server2: &Server2| server2.read_notifs(HashMap::from([(0u64, ls.clone())])).unwrap().remove(&0).unwrap();
    let served = read(&from_buckets);

    // Both ways of writing serve the same buckets, each one a bucket that was written.
    assert_eq!(served, read(&from_chunks));
    assert_eq!(served.len(), ls.len());
    for bucket in &served {
        assert_eq!(bucket.len(), Z_M);
        assert!(buckets.contains(bucket));
    }

    // The zero-copy read path serves the same bytes.
    let refs = from_chunks.read_notifs_refs(HashMap::from([(0u64, ls.clone())])).unwrap();
    let served_bytes: Vec<Vec<u8>> = served.iter().map(flatten).collect();
    assert_eq!(refs[&0], served_bytes.iter().map(|bytes| bytes.as_slice()).collect::<Vec<_>>());
}
