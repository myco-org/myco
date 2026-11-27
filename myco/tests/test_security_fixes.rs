//! Regression tests for the security fixes of November 2026 (audit items N1, N2, N3, N4/K6, K1, K7).
//! Each test names the item it covers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use myco::client::Client;
use myco::constants::*;
use myco::dtypes::{Bucket, Key, TreeMycoKey};
use myco::error::MycoError;
use myco::network::server1::{LocalServer1Access, Server1Access};
use myco::network::server2::{LocalServer2Access, Server2Access};
use myco::server1::{EpochWrite, Server1};
use myco::server2::Server2;
use myco::tree::SparseBinaryTree;
use myco::utils::Index;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tokio::sync::RwLock;

type R<T> = Result<T, MycoError>;

/// Server2 access that records what a client asks for and can be told to fail path reads.
#[derive(Clone)]
struct RecordingS2 {
    inner: LocalServer2Access,
    paths: Arc<Mutex<Vec<Vec<u8>>>>,
    notif_requests: Arc<Mutex<Vec<HashMap<u64, Vec<Index>>>>>,
    fail_reads: Arc<Mutex<bool>>,
}

#[async_trait]
impl Server2Access for RecordingS2 {
    async fn write(&self, p: &SparseBinaryTree<Bucket>, n: &Vec<Bucket>, k: &Key<TreeMycoKey>) -> R<()> {
        self.inner.write(p, n, k).await
    }
    async fn write_epoch(&self, e: Arc<EpochWrite>, k: &Key<TreeMycoKey>) -> R<()> {
        self.inner.write_epoch(e, k).await
    }
    async fn get_prf_keys(&self) -> R<Vec<Key<TreeMycoKey>>> {
        self.inner.get_prf_keys().await
    }
    async fn read_notifs(&self, ls: HashMap<u64, Vec<Index>>) -> R<HashMap<u64, Vec<Bucket>>> {
        self.notif_requests.lock().unwrap().push(ls.clone());
        self.inner.read_notifs(ls).await
    }
    async fn read(&self, l: Vec<u8>) -> R<Vec<Bucket>> {
        self.paths.lock().unwrap().push(l.clone());
        if *self.fail_reads.lock().unwrap() {
            return Err(MycoError::NetworkError("injected failure".to_string()));
        }
        self.inner.read(l).await
    }
    async fn get_mega_client_writes(&self) -> R<(Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Key<TreeMycoKey>>, Vec<Vec<u8>>)> {
        self.inner.get_mega_client_writes().await
    }
    async fn chunk_process_read(&self, a: Vec<Vec<u8>>, b: Vec<Vec<u8>>) -> R<(Vec<Bucket>, Vec<Bucket>, u32)> {
        self.inner.chunk_process_read(a, b).await
    }
    async fn process_read_indices(&self, a: Vec<Vec<u8>>) -> R<()> {
        self.inner.process_read_indices(a).await
    }
    async fn process_notification_indices(&self, a: Vec<Vec<u8>>) -> R<()> {
        self.inner.process_notification_indices(a).await
    }
    async fn get_all_client_prf_keys(&self, n: usize) -> R<()> {
        self.inner.get_all_client_prf_keys(n).await
    }
    async fn pre_generate_test_data(&self) -> R<bool> {
        self.inner.pre_generate_test_data().await
    }
}

/// One write as Server1 receives it: (ct, ct_ntf, f, f_ntf, k_renc_t, c_s).
type SeenWrite = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Server1 access that records every write and can replace a write's ciphertext by the
/// first one it saw (a Server1 that replays an old message).
#[derive(Clone)]
struct RecordingS1 {
    inner: LocalServer1Access,
    writes: Arc<Mutex<Vec<SeenWrite>>>,
    replay_first: Arc<Mutex<bool>>,
}

#[async_trait]
impl Server1Access for RecordingS1 {
    async fn queue_write(&self, ct: Vec<u8>, ct_ntf: Vec<u8>, f: Vec<u8>, f_ntf: Vec<u8>, k: Key<TreeMycoKey>, c_s: Vec<u8>) -> R<()> {
        let ct = if *self.replay_first.lock().unwrap() { self.writes.lock().unwrap()[0].0.clone() } else { ct };
        self.writes.lock().unwrap().push((ct.clone(), ct_ntf.clone(), f.clone(), f_ntf.clone(), k.bytes.clone(), c_s.clone()));
        self.inner.queue_write(ct, ct_ntf, f, f_ntf, k, c_s).await
    }
    async fn batch_init(&self) -> R<()> {
        self.inner.batch_init().await
    }
    async fn batch_write(&self) -> R<()> {
        self.inner.batch_write().await
    }
}

struct World {
    s1: Arc<RwLock<Server1>>,
    rec2: RecordingS2,
    rec1: RecordingS1,
}

fn world(num_clients: usize) -> World {
    let s2 = Arc::new(RwLock::new(Server2::new(num_clients)));
    let local = LocalServer2Access { server: s2.clone() };
    let s1 = Arc::new(RwLock::new(Server1::new(Box::new(local.clone()), num_clients)));
    let rec2 = RecordingS2 {
        inner: local,
        paths: Arc::new(Mutex::new(Vec::new())),
        notif_requests: Arc::new(Mutex::new(Vec::new())),
        fail_reads: Arc::new(Mutex::new(false)),
    };
    let rec1 = RecordingS1 {
        inner: LocalServer1Access { server: s1.clone() },
        writes: Arc::new(Mutex::new(Vec::new())),
        replay_first: Arc::new(Mutex::new(false)),
    };
    World { s1, rec2, rec1 }
}

fn client(w: &World, name: &str, num_clients: usize) -> Client {
    Client::new(name.to_string(), Box::new(w.rec1.clone()), Box::new(w.rec2.clone()), num_clients)
}

fn batch_init(w: &World) {
    w.s1.try_write().unwrap().batch_init().unwrap();
}

fn batch_write(w: &World) {
    w.s1.try_write().unwrap().batch_write().unwrap();
}

/// Two clients that share a key and list each other as their only contact.
fn pair(w: &World, seed: u64) -> (Client, Client) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let k = Key::<TreeMycoKey>::random(&mut rng);
    let mut alice = client(w, "Alice", 2);
    let mut bob = client(w, "Bob", 2);
    alice.setup(vec![k.clone()], vec!["Bob".to_string()]).unwrap();
    bob.setup(vec![k], vec!["Alice".to_string()]).unwrap();
    (alice, bob)
}

// ---------------------------------------------------------------------------------------------
// N1: the client's routing values f and f_ntf are full-length PRF outputs, Server1 accepts
// no other length, and notification indices are 8 bytes.
// ---------------------------------------------------------------------------------------------
#[test]
fn n1_routing_values_are_full_length() {
    let w = world(2);
    let (mut alice, mut bob) = pair(&w, 1);

    batch_init(&w);
    alice.write(b"hi", "Bob").unwrap();
    {
        let writes = w.rec1.writes.lock().unwrap();
        assert_eq!(writes[0].2.len(), LAMBDA_BYTES, "f");
        assert_eq!(writes[0].3.len(), LAMBDA_BYTES, "f_ntf");
    }
    batch_write(&w);
    bob.increment_epoch();
    assert_eq!(bob.read(Some(1)).unwrap(), b"hi".to_vec());

    for request in w.rec2.notif_requests.lock().unwrap().iter() {
        for indices in request.values() {
            assert!(indices.iter().all(|index| index.len() == NOTIF_LOC_BYTES));
        }
    }
    assert_eq!(NOTIF_LOC_BYTES, 8);
    assert!(w.rec2.paths.lock().unwrap().iter().all(|path| path.len() == D_BYTES));

    // Server1 turns away routing values of any other length, including the old 3 bytes.
    batch_init(&w);
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    for (f_len, f_ntf_len) in [(3, 3), (D_BYTES, LAMBDA_BYTES), (LAMBDA_BYTES, 8), (LAMBDA_BYTES + 1, LAMBDA_BYTES)] {
        let result = w.s1.try_write().unwrap().queue_write(
            vec![0u8; INNER_BLOCK_SIZE],
            vec![0u8; LAMBDA_BYTES],
            vec![7u8; f_len],
            vec![7u8; f_ntf_len],
            Key::random(&mut rng),
            b"Mallory".to_vec(),
        );
        assert!(result.is_err(), "f of {} bytes and f_ntf of {} bytes were accepted", f_len, f_ntf_len);
    }
    w.s1.try_write().unwrap().queue_write(
        vec![0u8; INNER_BLOCK_SIZE],
        vec![0u8; LAMBDA_BYTES],
        vec![7u8; LAMBDA_BYTES],
        vec![7u8; LAMBDA_BYTES],
        Key::random(&mut rng),
        b"Mallory".to_vec(),
    ).unwrap();
}

// ---------------------------------------------------------------------------------------------
// N2: the client remembers what it has read. With two unread messages it delivers each once,
// oldest first, and never asks Server2 for the same path twice.
// ---------------------------------------------------------------------------------------------
#[test]
fn n2_each_message_is_read_once() {
    let w = world(1);
    let mut alice = client(&w, "Alice", 1);
    let mut rng = ChaCha20Rng::seed_from_u64(4);
    alice.setup(vec![Key::random(&mut rng)], vec!["Alice".to_string()]).unwrap();
    for message in [b"first".to_vec(), b"second".to_vec()] {
        batch_init(&w);
        alice.write(&message, "Alice").unwrap();
        batch_write(&w);
    }
    let delivered: Vec<Vec<u8>> = (0..12).map(|_| alice.read(Some(2)).unwrap()).collect();
    assert_eq!(delivered[0], b"first".to_vec());
    assert_eq!(delivered[1], b"second".to_vec());
    assert!(delivered[2..].iter().all(|message| message.is_empty()), "a message was delivered twice");

    let paths = w.rec2.paths.lock().unwrap().clone();
    assert_eq!(paths.len(), 12, "one path request per read");
    let mut distinct = paths.clone();
    distinct.sort();
    distinct.dedup();
    // The two real paths differ, and the ten fake ones are uniform (a collision among twelve
    // 18-bit values has probability below 0.03%).
    assert_ne!(paths[0], paths[1]);
    assert_eq!(distinct.len(), 12, "a path was requested twice");
}

// A message found in one call and not yet read is read by a later call, even when that later
// call looks back fewer epochs than the message's age.
#[test]
fn n2_pending_message_survives_a_shorter_lookback() {
    let w = world(1);
    let mut alice = client(&w, "Alice", 1);
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    alice.setup(vec![Key::random(&mut rng)], vec!["Alice".to_string()]).unwrap();
    for message in [b"first".to_vec(), b"second".to_vec()] {
        batch_init(&w);
        alice.write(&message, "Alice").unwrap();
        batch_write(&w);
    }
    assert_eq!(alice.read(Some(2)).unwrap(), b"first".to_vec());
    // An epoch without a write from Alice: "second" is now two epochs back.
    batch_init(&w);
    batch_write(&w);
    alice.increment_epoch();
    assert_eq!(alice.read(Some(1)).unwrap(), b"second".to_vec());
    assert!(alice.read(Some(1)).unwrap().is_empty());
    assert!(alice.read(Some(3)).unwrap().is_empty());
}

// ---------------------------------------------------------------------------------------------
// N3: when Server2 fails a path read, a client doing a fake read behaves like one doing a
// real read: neither panics, and both go on to the next epoch.
// ---------------------------------------------------------------------------------------------
#[test]
fn n3_failed_path_read_does_not_panic_whether_real_or_fake() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    let mut rng = ChaCha20Rng::seed_from_u64(9);

    // Real read.
    let w = world(1);
    let mut alice = client(&w, "Alice", 1);
    alice.setup(vec![Key::random(&mut rng)], vec!["Alice".to_string()]).unwrap();
    batch_init(&w);
    alice.write(b"x", "Alice").unwrap();
    batch_write(&w);
    *w.rec2.fail_reads.lock().unwrap() = true;
    let real = catch_unwind(AssertUnwindSafe(|| alice.read(Some(1))));
    assert!(matches!(real, Ok(Err(_))), "a failed real read returns an error");

    // Fake read.
    let w = world(1);
    let mut bob = client(&w, "Bob", 1);
    bob.setup(vec![Key::random(&mut rng)], vec!["Bob".to_string()]).unwrap();
    batch_init(&w);
    batch_write(&w);
    bob.increment_epoch();
    *w.rec2.fail_reads.lock().unwrap() = true;
    let fake = catch_unwind(AssertUnwindSafe(|| bob.read(Some(1))));
    assert!(matches!(fake, Ok(Err(_))), "a failed fake read returns an error, as a failed real read does");
    assert!(catch_unwind(AssertUnwindSafe(|| bob.fake_read())).map(|r| r.is_err()).unwrap_or(false), "fake_read reports the failure");
    assert_eq!(w.rec2.paths.lock().unwrap().len(), 2, "both fake reads reached Server2");

    // Both clients carry on in the next epoch.
    *w.rec2.fail_reads.lock().unwrap() = false;
    batch_init(&w);
    batch_write(&w);
    bob.increment_epoch();
    assert!(bob.read(Some(1)).unwrap().is_empty());
}

// ---------------------------------------------------------------------------------------------
// N4 / K6: the epoch is authenticated with the message. A Server1 that puts an earlier
// ciphertext of the conversation in place of a new one does not get it accepted.
// ---------------------------------------------------------------------------------------------
#[test]
fn n4_server1_cannot_replay_an_old_ciphertext() {
    let w = world(2);
    let (mut alice, mut bob) = pair(&w, 13);

    batch_init(&w);
    alice.write(b"transfer 1", "Bob").unwrap();
    batch_write(&w);
    bob.increment_epoch();
    assert_eq!(bob.read(Some(1)).unwrap(), b"transfer 1".to_vec());

    // Epoch 1: Alice sends "hello"; Server1 substitutes the epoch-0 ciphertext and keeps
    // everything else of Alice's epoch-1 write.
    *w.rec1.replay_first.lock().unwrap() = true;
    batch_init(&w);
    alice.write(b"hello", "Bob").unwrap();
    batch_write(&w);
    {
        let writes = w.rec1.writes.lock().unwrap();
        assert_eq!(writes[1].0, writes[0].0, "the test did replay the first ciphertext");
    }
    bob.increment_epoch();
    let second = bob.read(Some(1));
    assert!(second.is_err(), "Bob accepted a replayed message: {:?}", second.map(|m| String::from_utf8_lossy(&m).to_string()));
}

// The associated data is part of what is authenticated, and the plain functions use none.
#[test]
fn n4_associated_data_is_checked() {
    use myco::crypto::{decrypt, decrypt_with_aad, encrypt, encrypt_with_aad};
    let key = [9u8; LAMBDA_BYTES];
    let ct = encrypt_with_aad(&key, b"m", MESSAGE_SIZE, &5u64.to_be_bytes()).unwrap();
    assert!(decrypt_with_aad(&key, &ct, &5u64.to_be_bytes()).is_ok());
    assert!(decrypt_with_aad(&key, &ct, &6u64.to_be_bytes()).is_err());
    assert!(decrypt(&key, &ct).is_err());
    let plain = encrypt(&key, b"m", MESSAGE_SIZE).unwrap();
    assert_eq!(plain.len(), ct.len(), "associated data does not change the ciphertext length");
    assert!(decrypt(&key, &plain).is_ok());
    assert!(decrypt_with_aad(&key, &plain, b"").is_ok());
}

// ---------------------------------------------------------------------------------------------
// K1: fake writes and fake reads are requests of exactly the same encoded length as real ones.
// ---------------------------------------------------------------------------------------------
#[test]
fn k1_fake_and_real_requests_have_the_same_length() {
    use myco::proto::myco as proto;
    use prost::Message;

    let w = world(2);
    let (mut alice, mut bob) = pair(&w, 21);

    batch_init(&w);
    alice.write(b"a real message", "Bob").unwrap();
    bob.fake_write().unwrap();
    batch_write(&w);
    bob.increment_epoch();
    alice.increment_epoch();

    let encoded: Vec<usize> = w.rec1.writes.lock().unwrap().iter().map(|(ct, ct_ntf, f, f_ntf, k, _c_s)| {
        // Field by field first, so that a difference is reported where it is.
        assert_eq!((ct.len(), ct_ntf.len(), f.len(), f_ntf.len(), k.len()), (INNER_BLOCK_SIZE, LAMBDA_BYTES, LAMBDA_BYTES, LAMBDA_BYTES, LAMBDA_BYTES));
        proto::QueueWriteRequest {
            ct: ct.clone(),
            ct_ntf: ct_ntf.clone(),
            f: f.clone(),
            f_ntf: f_ntf.clone(),
            k_renc_t: Some(Key::<TreeMycoKey>::new(k.clone()).into()),
            // The two senders' names differ in length; the request is compared without them.
            c_s: Vec::new(),
        }.encoded_len()
    }).collect();
    assert_eq!(encoded.len(), 2);
    assert_eq!(encoded[0], encoded[1], "real and fake write requests differ in length");

    // Bob's read is real (Alice wrote to him), Alice's is fake (nobody wrote to her).
    assert_eq!(bob.read(Some(1)).unwrap(), b"a real message".to_vec());
    assert!(alice.read(Some(1)).unwrap().is_empty());
    alice.fake_read().unwrap();
    let paths = w.rec2.paths.lock().unwrap().clone();
    assert_eq!(paths.len(), 3);
    let lengths: Vec<usize> = paths.iter().map(|path| proto::ReadRequest { index: path.clone() }.encoded_len()).collect();
    assert!(paths.iter().all(|path| path.len() == D_BYTES), "path lengths {:?}", paths.iter().map(|p| p.len()).collect::<Vec<_>>());
    assert!(lengths.iter().all(|&length| length == lengths[0]), "real and fake read requests differ in length: {:?}", lengths);
}

// ---------------------------------------------------------------------------------------------
// K7: a notification request holds exactly Q indices per epoch, whatever the number of
// contacts, and a contact has no fixed position in it.
// ---------------------------------------------------------------------------------------------
#[test]
fn k7_notification_requests_are_padded_to_q_and_shuffled() {
    let w = world(2);
    let (mut alice, mut bob) = pair(&w, 31);

    // Several epochs, Alice writes to Bob in each; Bob looks back over all of them every time.
    let epochs = 6;
    for epoch in 0..epochs {
        batch_init(&w);
        alice.write(format!("m{}", epoch).as_bytes(), "Bob").unwrap();
        batch_write(&w);
        bob.increment_epoch();
        assert_eq!(bob.read(Some(epoch + 1)).unwrap(), format!("m{}", epoch).into_bytes(), "delivery with padded requests");
    }

    let requests = w.rec2.notif_requests.lock().unwrap().clone();
    assert_eq!(requests.len(), epochs);
    for (i, request) in requests.iter().enumerate() {
        assert_eq!(request.len(), i + 1, "one list per epoch looked back");
        for indices in request.values() {
            assert_eq!(indices.len(), Q, "a client with one contact still asks for Q buckets");
            assert!(indices.iter().all(|index| index.len() == NOTIF_LOC_BYTES));
        }
    }

    // Bob asks for epoch 0 in all six reads (look-back i + 1 in read i). The padding of an epoch
    // is derived from Bob's secret and the epoch, so all six requests hold the same Q indices:
    // comparing them does not single out the contact's index. Only the order changes.
    let lists: Vec<&Vec<Index>> = requests.iter().enumerate().map(|(i, request)| &request[&(i as u64 + 1)]).collect();
    let sorted = |list: &Vec<Index>| { let mut l = list.clone(); l.sort(); l };
    for list in &lists[1..] {
        assert_eq!(sorted(list), sorted(lists[0]), "a repeated look-back must send the same set of indices");
    }
    assert!(lists.iter().any(|list| list != &lists[0]), "the order is shuffled on every request");
    // Every index is a notification location in range, like a real one.
    let m = (Q * 2) as u64; // world(2)
    assert!(lists.iter().flat_map(|l| l.iter()).all(|index| u64::from_le_bytes(index[..8].try_into().unwrap()) < m));
}

// ---------------------------------------------------------------------------------------------
// N5: a location is the routing value plus a pad that depends only on Server1's epoch key and
// the sender: l = f XOR PRF_k(0 || c_s) in the tree, l_ntf = f_ntf + PRF_k(1 || c_s) mod Q*N for
// notifications. Server2, which learns k, can compute every sender's pad, but for any location
// and any sender there is exactly one routing value that gives it, so with f secret and uniform
// the location says nothing about the sender.
// ---------------------------------------------------------------------------------------------
#[test]
fn n5_location_is_routing_value_plus_a_pad() {
    use myco::utils::{notification_location, tree_location};
    let mut rng = ChaCha20Rng::seed_from_u64(55);
    let k = Key::<TreeMycoKey>::random(&mut rng).bytes;
    let num_clients = 1000;
    let m = (Q * num_clients) as u128;
    let value = |index: &Vec<u8>| u64::from_le_bytes(index[..8].try_into().unwrap()) as u128;
    let random = |rng: &mut ChaCha20Rng| -> Vec<u8> { { let mut v = vec![0u8; LAMBDA_BYTES]; rand::RngCore::fill_bytes(rng, &mut v); v } };

    for sender in [b"Alice".to_vec(), b"Bob".to_vec()] {
        let f0 = random(&mut rng);
        let tree_pad: Vec<u8> = tree_location(&k, &f0, &sender).unwrap().iter().zip(&f0).map(|(l, f)| l ^ f).collect();
        let ntf_of = |f: &[u8]| u128::from_le_bytes(f.try_into().unwrap()) % m;
        let ntf_pad = (value(&notification_location(&k, &f0, &sender, num_clients).unwrap()) + m - ntf_of(&f0)) % m;
        for _ in 0..200 {
            let f = random(&mut rng);
            let l = tree_location(&k, &f, &sender).unwrap();
            assert_eq!(l.len(), D_BYTES);
            let pad: Vec<u8> = l.iter().zip(&f).map(|(l, f)| l ^ f).collect();
            assert_eq!(pad, tree_pad, "the tree pad depends only on k and the sender");
            let l_ntf = notification_location(&k, &f, &sender, num_clients).unwrap();
            assert_eq!(l_ntf.len(), NOTIF_LOC_BYTES);
            assert!(value(&l_ntf) < m);
            assert_eq!((value(&l_ntf) + m - ntf_of(&f)) % m, ntf_pad, "the notification pad depends only on k and the sender");
        }
    }
    // Different senders and different epoch keys give different pads.
    let f = random(&mut rng);
    assert_ne!(tree_location(&k, &f, b"Alice").unwrap(), tree_location(&k, &f, b"Bob").unwrap());
    let k2 = Key::<TreeMycoKey>::random(&mut rng).bytes;
    assert_ne!(tree_location(&k, &f, b"Alice").unwrap(), tree_location(&k2, &f, b"Alice").unwrap());
}
