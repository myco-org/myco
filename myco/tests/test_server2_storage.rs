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

#[test]
fn staged_epoch_is_served_only_once_it_is_finalized() {
    use myco::constants::D_BYTES;
    use myco::dtypes::{Key, TreeMycoKey};

    let num_clients = 3;
    let num_buckets = num_clients * Q;
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let mut server2 = Server2::new(num_clients);

    let leftmost_path = vec![0u8; D_BYTES];
    let tree_bucket = |rng: &mut ChaCha20Rng| Bucket::contiguous(random_bytes(Z * BLOCK_SIZE, rng), Some(random_bytes(64, rng)));
    let notifs_of = |server2: &Server2, epochs_back: u64, ls: &Vec<Vec<u8>>| {
        server2.read_notifs(HashMap::from([(epochs_back, ls.clone())])).unwrap().remove(&epochs_back).unwrap()
    };
    let ls: Vec<Vec<u8>> = (0..50).map(|_| random_bytes(8, &mut rng)).collect();
    let as_buckets = |raw: &[u8]| -> Vec<Vec<u8>> { raw.chunks(NOTIFICATION_BUCKET_SIZE_BYTES).map(|bucket| bucket.to_vec()).collect() };

    let before = server2.read(leftmost_path.clone()).unwrap();

    // First epoch: the root and its left child, in two chunks, and a notification table in two chunks.
    let (root_1, child_1) = (tree_bucket(&mut rng), tree_bucket(&mut rng));
    let raw_1 = random_bytes(num_buckets * NOTIFICATION_BUCKET_SIZE_BYTES, &mut rng);
    let split = (num_buckets / 2) * NOTIFICATION_BUCKET_SIZE_BYTES;
    server2.stage_chunk_write(vec![child_1.clone()], vec![2]);
    server2.stage_chunk_write(vec![root_1.clone()], vec![1]);
    server2.stage_notifs_chunk(num_buckets / 2, &raw_1[split..]);
    server2.stage_notifs_chunk(0, &raw_1[..split]);

    // Nothing staged is visible yet.
    assert_eq!(server2.read(leftmost_path.clone()).unwrap(), before);
    assert!(notifs_of(&server2, 1, &ls).is_empty());

    server2.finalize_epoch(&Key::<TreeMycoKey>::random(&mut rng));
    let after_1 = server2.read(leftmost_path.clone()).unwrap();
    assert_eq!(&after_1[..2], &[root_1.clone(), child_1.clone()]);
    assert_eq!(&after_1[2..], &before[2..]);
    let served_1 = notifs_of(&server2, 1, &ls);
    assert_eq!(served_1.len(), ls.len());
    let buckets_1 = as_buckets(&raw_1);
    assert!(served_1.iter().all(|bucket| buckets_1.contains(&flatten(bucket))));

    // Second epoch: a new root only. Until it is finalized the first epoch is still served.
    let root_2 = tree_bucket(&mut rng);
    let raw_2 = random_bytes(num_buckets * NOTIFICATION_BUCKET_SIZE_BYTES, &mut rng);
    server2.stage_chunk_write(vec![root_2.clone()], vec![1]);
    server2.stage_notifs_chunk(0, &raw_2);
    assert_eq!(server2.read(leftmost_path.clone()).unwrap(), after_1);
    assert_eq!(notifs_of(&server2, 1, &ls), served_1);

    server2.finalize_epoch(&Key::<TreeMycoKey>::random(&mut rng));
    let after_2 = server2.read(leftmost_path.clone()).unwrap();
    assert_eq!(&after_2[..2], &[root_2, child_1]);
    let buckets_2 = as_buckets(&raw_2);
    assert!(notifs_of(&server2, 1, &ls).iter().all(|bucket| buckets_2.contains(&flatten(bucket))));
    // The first epoch's notifications are now one epoch further back.
    assert_eq!(notifs_of(&server2, 2, &ls), served_1);
}

#[test]
fn recycled_buffers_never_change_what_the_tree_serves() {
    use myco::constants::D_BYTES;
    use myco::dtypes::{Key, TreeMycoKey};

    let mut rng = ChaCha20Rng::seed_from_u64(4);
    let mut server2 = Server2::new(3);
    let wire = |rng: &mut ChaCha20Rng| proto::Bucket { data: random_bytes(Z * BLOCK_SIZE, rng), signature: random_bytes(64, rng) };
    // The buckets on the leftmost path, as wire buckets.
    let served = |server2: &Server2| -> Vec<proto::Bucket> { server2.read(vec![0u8; D_BYTES]).unwrap().iter().map(proto::Bucket::from).collect() };
    let finalize = |server2: &mut Server2| server2.finalize_epoch(&Key::<TreeMycoKey>::random(&mut ChaCha20Rng::seed_from_u64(9)));

    // Tree indices 1, 2 and 4 are the first three buckets of the leftmost path.
    let mut expected = [wire(&mut rng), wire(&mut rng), wire(&mut rng)];
    server2.stage_wire_chunk(expected.to_vec(), vec![1, 2, 4]);
    finalize(&mut server2);
    assert_eq!(&served(&server2)[..3], &expected[..]);

    // Every later epoch rewrites some of the three. From the second such epoch on, the new
    // buckets are copied into buffers that held earlier versions; a bucket that is not
    // rewritten must keep its contents all the same.
    for epoch in 0..12usize {
        let rewritten: Vec<usize> = (0..3).filter(|i| (epoch + i) % 3 != 0).collect();
        let fresh: Vec<proto::Bucket> = rewritten.iter().map(|_| wire(&mut rng)).collect();
        // Staging alone changes nothing that is served.
        server2.stage_wire_chunk(fresh.clone(), rewritten.iter().map(|&i| [1usize, 2, 4][i]).collect());
        assert_eq!(&served(&server2)[..3], &expected[..], "epoch {} before it is finalized", epoch);
        finalize(&mut server2);
        for (&i, bucket) in rewritten.iter().zip(fresh) {
            expected[i] = bucket;
        }
        assert_eq!(&served(&server2)[..3], &expected[..], "epoch {}", epoch);
    }
}

#[test]
fn an_incomplete_epoch_is_never_applied() {
    use myco::constants::D_BYTES;
    use myco::dtypes::{Key, TreeMycoKey};

    let num_clients = 3;
    let notif_bytes = num_clients * Q * NOTIFICATION_BUCKET_SIZE_BYTES;
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    let mut server2 = Server2::new(num_clients);
    let wire = |rng: &mut ChaCha20Rng| proto::Bucket { data: random_bytes(Z * BLOCK_SIZE, rng), signature: random_bytes(64, rng) };
    let served = |server2: &Server2| -> Vec<proto::Bucket> { server2.read(vec![0u8; D_BYTES]).unwrap().iter().map(proto::Bucket::from).collect() };
    let key = |rng: &mut ChaCha20Rng| Key::<TreeMycoKey>::random(rng);

    // A complete epoch of three buckets is applied.
    let first = [wire(&mut rng), wire(&mut rng), wire(&mut rng)];
    server2.stage_wire_chunk(first.to_vec(), vec![1, 2, 4]);
    server2.stage_notifs_chunk(0, &random_bytes(notif_bytes, &mut rng));
    server2.finalize_epoch_checked(&key(&mut rng), 3).unwrap();
    assert_eq!(&served(&server2)[..3], &first[..]);
    let (epoch, keys) = (server2.epoch, server2.get_prf_keys().unwrap().len());

    // The next epoch breaks off after one of its three buckets: nothing changes.
    let broken = wire(&mut rng);
    server2.stage_wire_chunk(vec![broken.clone()], vec![1]);
    server2.stage_notifs_chunk(0, &random_bytes(notif_bytes / 2, &mut rng));
    assert!(server2.finalize_epoch_checked(&key(&mut rng), 3).is_err());
    assert_eq!(&served(&server2)[..3], &first[..]);
    assert_eq!((server2.epoch, server2.get_prf_keys().unwrap().len()), (epoch, keys));

    // Its chunk is not mixed into the epoch that follows, which is applied whole.
    let second = [wire(&mut rng), wire(&mut rng), wire(&mut rng)];
    server2.stage_wire_chunk(second.to_vec(), vec![1, 2, 4]);
    server2.stage_notifs_chunk(0, &random_bytes(notif_bytes, &mut rng));
    server2.finalize_epoch_checked(&key(&mut rng), 3).unwrap();
    assert_eq!(&served(&server2)[..3], &second[..]);
    assert_eq!(server2.epoch, epoch + 1);

    // A missing notification chunk alone is also refused.
    server2.stage_wire_chunk(vec![wire(&mut rng)], vec![1]);
    server2.stage_notifs_chunk(0, &random_bytes(notif_bytes - NOTIFICATION_BUCKET_SIZE_BYTES, &mut rng));
    assert!(server2.finalize_epoch_checked(&key(&mut rng), 1).is_err());
    assert_eq!(&served(&server2)[..3], &second[..]);
}
