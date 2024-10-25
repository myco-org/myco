use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use error::OramError;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use ring::{digest, hkdf, pbkdf2};
use std::{
    collections::HashMap,
    num::NonZeroU32,
    sync::{Arc, Mutex},
};
use thiserror::Error;

// Add module declarations
mod constants;
mod dtypes;
mod error;
mod server1;
mod server2;
mod tree;

// Import constants and server modules
use constants::*;
use dtypes::*;
use server1::Server1;
use server2::Server2;

// Key Derivation Function (KDF)
fn kdf(key: &[u8], info: &str) -> Result<Vec<u8>, OramError> {
    let salt = digest::digest(&digest::SHA256, b"MC-OSAM-Salt");
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt.as_ref()).extract(key);
    let binding = [info.as_bytes()];
    let okm = prk
        .expand(&binding, hkdf::HKDF_SHA256)
        .map_err(|_| OramError::HkdfExpansionFailed)?;
    let mut result = vec![0u8; 32];
    okm.fill(&mut result)
        .map_err(|_| OramError::HkdfFillFailed)?;
    Ok(result[..16].to_vec())
}

// Pseudorandom Function (PRF)
// Make this an arbitrary-length PRF
fn prf(key: &[u8], input: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(1000).unwrap(),
        key,
        input,
        &mut result,
    );
    result
}

// Pad a message to the right with zeros
fn pad_message(message: &[u8], target_length: usize) -> Vec<u8> {
    let mut padded = message.to_vec();
    if padded.len() < target_length {
        padded.resize(target_length, 0);
    }
    padded
}

pub(crate) enum EncryptionType {
    Encrypt,
    DoubleEncrypt,
}

// Encrypt a padded message
fn encrypt(
    key: &[u8],
    message: &[u8],
    encryption_type: EncryptionType,
) -> Result<Vec<u8>, OramError> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| OramError::EncryptionFailed)?;

    let binding = rand::thread_rng().gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&binding); // 96-bits; unique per message
    let mut buffer = match encryption_type {
        EncryptionType::Encrypt => pad_message(message, BLOCK_SIZE), // Fixed size buffer for message
        EncryptionType::DoubleEncrypt => pad_message(message, INNER_BLOCK_SIZE), // Fixed size buffer for message
    };

    cipher
        .encrypt_in_place(nonce, b"", &mut buffer)
        .map_err(|_| OramError::EncryptionFailed)?;

    // Prepend the nonce to the ciphertext to use during decryption
    Ok([nonce.as_slice(), buffer.as_slice()].concat())
}

// Decrypt a ciphertext
fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, OramError> {
    if ciphertext.len() < 12 {
        return Err(OramError::NoMessageFound);
    }

    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| OramError::NoMessageFound)?;
    let (nonce, ciphertext) = ciphertext.split_at(12); // Extract nonce and ciphertext
    let nonce = Nonce::from_slice(nonce);
    let mut buffer = Vec::from(ciphertext);

    cipher
        .decrypt_in_place(nonce, b"", &mut buffer)
        .map_err(|_| OramError::NoMessageFound)?;

    Ok(buffer)
}

fn trim_zeros(buffer: &[u8]) -> Vec<u8> {
    let buf: Vec<u8> = buffer
        .iter()
        .rev()
        .skip_while(|&&x| x == 0)
        .cloned()
        .collect();
    buf.into_iter().rev().collect()
}

struct Client {
    id: String,
    epoch: usize,
    keys: HashMap<Key, (Vec<u8>, Vec<u8>, Vec<u8>)>,
    s1: Arc<Mutex<Server1>>,
    s2: Arc<Mutex<Server2>>,
}

impl Client {
    fn new(id: String, s1: Arc<Mutex<Server1>>, s2: Arc<Mutex<Server2>>) -> Self {
        Client {
            id,
            epoch: 0,
            keys: HashMap::new(),
            s1,
            s2,
        }
    }

    fn setup(&mut self, k: &Key) -> Result<(), OramError> {
        let k_msg = kdf(&k.0, "MSG")?;
        let k_oram = kdf(&k.0, "ORAM")?;
        let k_prf = kdf(&k.0, "PRF")?;
        self.keys.insert(k.clone(), (k_msg, k_oram, k_prf));
        Ok(())
    }

    fn write(&mut self, msg: &[u8], k: &Key) -> Result<(), OramError> {
        let epoch = self.epoch;
        let cs = self.id.clone().into_bytes();

        // 1: {kmsg, koram, kprf } ← keys[k]
        let (k_msg, k_oram, k_prf) = self.keys.get(k).unwrap();

        // 2: ℓ = PRF_kprf (t)
        let f = prf(k_prf, &epoch.to_be_bytes());

        // 3: koram,t = KDF(koram, t)
        let k_oram_t = kdf(k_oram, &epoch.to_string())?;

        // 4: ct = Enckmsg (m)
        let ct = encrypt(k_msg, msg, EncryptionType::Encrypt)?;

        self.epoch += 1;
        // 5: return S1.Write(ct, ℓ, koram,t)
        self.s1.lock().unwrap().write(ct, f, Key::new(k_oram_t), cs)
    }

    fn read(&self, k: &Key, cs: String, epoch_past: usize) -> Result<Vec<u8>, OramError> {
        // Use the passed epoch if available, otherwise default to self.epoch - 1
        let epoch = self.epoch - 1 - epoch_past;
        let cs = cs.into_bytes();

        // 1: koram,t = KDF(koram, t)
        let (k_msg, k_oram, k_prf) = self.keys.get(&k).unwrap();
        let k_oram_t = kdf(k_oram, &epoch.to_string()).map_err(|_| OramError::NoMessageFound)?;

        let f = prf(&k_prf, &epoch.to_be_bytes());

        let keys: Vec<Key> = self.s2.lock().unwrap().get_prf_keys();
        let k_s1_t = keys.get(keys.len() - 1 - epoch_past).unwrap();

        // 2: ℓ = PRFkprf (t)
        let l = prf(k_s1_t.0.as_slice(), &[&f[..], &cs[..]].concat());

        let l_path = Path::from(l);

        // 3: p ← S2.Read(ℓ)
        let path = self.s2.lock().unwrap().read(&l_path);

        // 4: for block ∈ p do
        for bucket in path {
            for block in bucket {
                if let Ok(ct) = decrypt(&k_oram_t, &block.0) {
                    return decrypt(k_msg, &ct).map(|buf| trim_zeros(&buf));
                }
            }
        }
        // 8: end for

        Err(OramError::NoMessageFound)
    }

    fn fake_write(&self) -> Result<(), OramError> {
        let mut rng = ChaCha20Rng::from_entropy();
        let l: Vec<u8> = (0..D).map(|_| rng.gen()).collect();
        let k_oram_t = Key::random(&mut rng);
        let ct: Vec<u8> = (0..BLOCK_SIZE).map(|_| rng.gen()).collect();
        let cs = self.id.clone().into_bytes();
        self.s1.lock().unwrap().write(ct, l, k_oram_t, cs)
    }

    fn fake_read(&self) -> Vec<Bucket> {
        // 1: ℓ′ $ ←− {0, 1}^D
        let mut rng = ChaCha20Rng::from_entropy();
        let l: Vec<u8> = (0..D).map(|_| rng.gen()).collect();
        // 2: S2.Read(ℓ′)
        self.s2.lock().unwrap().read(&Path::from(l))
    }
}

#[cfg(test)]
mod util_tests {
    use super::*;
    use rand::{thread_rng, RngCore};

    #[test]
    fn test_kdf() {
        let key = b"original key";
        let info1 = "purpose1";
        let info2 = "purpose2";

        let derived1 = kdf(key, info1).expect("KDF failed");
        let derived2 = kdf(key, info2).expect("KDF failed");

        assert_ne!(derived1, derived2);
        assert_eq!(derived1.len(), 16);
        assert_eq!(derived2.len(), 16);
    }

    #[test]
    fn test_prf() {
        let key = b"prf key";
        let input1 = b"input1";
        let input2 = b"input2";

        let output1 = prf(key, input1);
        let output2 = prf(key, input2);

        assert_ne!(output1, output2);
        assert_eq!(output1.len(), 32);
        assert_eq!(output2.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_with_kdf_key() {
        // Test with KDF-derived key
        let key = kdf(b"encryption key", "enc").expect("KDF failed");

        let messages = vec![
            b"".to_vec(),
            b"1".to_vec(),
            b"1234".to_vec(),
            b"This is a longer message with multiple words.".to_vec(),
        ];

        for message in messages {
            let ciphertext =
                encrypt(&key, &message, EncryptionType::Encrypt).expect("Encryption failed");
            let decrypted = trim_zeros(&decrypt(&key, &ciphertext).expect("Decryption failed"));

            assert_ne!(ciphertext, message);
            assert_eq!(decrypted, message);
        }
    }

    #[test]
    fn test_encrypt_decrypt_with_random_key() {
        let mut rng = thread_rng();
        let random_key = Key::random(&mut rng);

        // Test with different message lengths
        let message_lengths: Vec<usize> = (0..BLOCK_SIZE).collect();

        for &length in &message_lengths {
            let random_message: Vec<u8> = (0..length)
                .map(|_| (rng.next_u32() % 255 + 1) as u8)
                .collect();

            let random_ciphertext =
                encrypt(&random_key.0, &random_message, EncryptionType::Encrypt)
                    .expect("Encryption failed");
            let random_decrypted =
                decrypt(&random_key.0, &random_ciphertext).expect("Decryption failed");

            assert_ne!(random_ciphertext, random_message);
            assert_eq!(trim_zeros(&random_decrypted), random_message);
        }
    }
}

mod e2e_tests {
    use rand::RngCore;

    use super::*;

    fn try_to_decrypt_data_on_path(
        path: Vec<Bucket>,
        k_oram_t: &Key,
        k_msg: &Key,
    ) -> Result<Vec<u8>, OramError> {
        for bucket in path {
            for block in bucket {
                if let Ok(c_msg) = decrypt(&k_oram_t.0, &block.0) {
                    return decrypt(&k_msg.0, &c_msg);
                }
            }
        }
        Err(OramError::NoMessageFound)
    }

    #[test]
    fn test_client_setup() {
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s1 = Arc::new(Mutex::new(Server1::new(s2.clone())));
        let mut alice = Client::new("Alice".to_string(), s1, s2);
        let mut rng = ChaCha20Rng::from_entropy();
        let k = Key::random(&mut rng);
        alice.setup(&k).expect("Setup failed");
        assert!(alice.keys.contains_key(&k));
    }

    #[test]
    fn test_write_and_read() {
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s1 = Arc::new(Mutex::new(Server1::new(s2.clone())));
        let mut alice = Client::new("Alice".to_string(), s1.clone(), s2);
        let mut rng = ChaCha20Rng::from_entropy();
        let k = Key::random(&mut rng);
        alice.setup(&k).expect("Setup failed");

        s1.lock().unwrap().batch_init(1);

        alice.write(&[1], &k).expect("Write failed");
        s1.lock().unwrap().batch_write();

        let msg = alice.read(&k, "Alice".to_string(), 0).expect("Read failed");
        assert_eq!(msg, vec![1]);
    }

    #[test]
    fn test_multiple_clients_one_epoch() {
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s1 = Arc::new(Mutex::new(Server1::new(s2.clone())));
        let mut alice = Client::new("Alice".to_string(), s1.clone(), s2.clone());
        let mut bob = Client::new("Bob".to_string(), s1.clone(), s2.clone());

        let mut rng: ChaCha20Rng = ChaCha20Rng::from_entropy();
        let k1 = Key::random(&mut rng);
        let mut rng: ChaCha20Rng = ChaCha20Rng::from_entropy();
        let k2 = Key::random(&mut rng);

        alice.setup(&k1).expect("Setup failed");
        alice.setup(&k2).expect("Setup failed");

        bob.setup(&k1).expect("Setup failed");
        bob.setup(&k2).expect("Setup failed");

        s1.lock().unwrap().batch_init(2);

        alice.write(&[1], &k1).expect("Write failed");
        bob.write(&[2], &k2).expect("Write failed");

        s1.lock().unwrap().batch_write();

        let msg = alice.read(&k2, "Bob".to_string(), 0).expect("Read failed");
        assert_eq!(msg, vec![2]);

        let msg = bob.read(&k1, "Alice".to_string(), 0).expect("Read failed");
        assert_eq!(msg, vec![1]);
    }

    #[test]
    fn test_multiple_writes_and_reads() {
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s1 = Arc::new(Mutex::new(Server1::new(s2.clone())));
        let mut alice = Client::new("Alice".to_string(), s1.clone(), s2);

        let num_operations = 5;

        // Perform multiple writes
        for i in 0..num_operations {
            let mut rng = ChaCha20Rng::from_entropy();
            let k = Key::random(&mut rng);
            let msg = vec![i as u8, (i + 1) as u8, (i + 2) as u8];

            alice.setup(&k).expect("Setup failed");
            s1.lock().unwrap().batch_init(1);
            alice.write(&msg, &k).expect("Write failed");
            s1.lock().unwrap().batch_write();
            let read_msg = alice.read(&k, "Alice".to_string(), 0).expect("Read failed");

            assert_eq!(
                read_msg, msg,
                "Read message doesn't match written message for key {}",
                i
            );
        }
    }

    #[test]
    fn test_multiple_clients_multiple_epochs() {
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s1 = Arc::new(Mutex::new(Server1::new(s2.clone())));

        let mut alice = Client::new("Alice".to_string(), s1.clone(), s2.clone());
        let mut bob = Client::new("Bob".to_string(), s1.clone(), s2.clone());

        let mut rng = ChaCha20Rng::from_entropy();

        // Initialize the first epoch

        for _ in 0..5 {
            s1.lock().unwrap().batch_init(2);

            // Perform writes for both clients
            let k_alice_to_bob = Key::random(&mut rng);
            let k_bob_to_alice = Key::random(&mut rng);

            alice.setup(&k_alice_to_bob).expect("Setup failed");
            alice.setup(&k_bob_to_alice).expect("Setup failed");

            bob.setup(&k_bob_to_alice).expect("Setup failed");
            bob.setup(&k_alice_to_bob).expect("Setup failed");

            let alice_msg: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
            let bob_msg: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
            alice
                .write(&alice_msg, &k_alice_to_bob)
                .expect("Write failed");
            bob.write(&bob_msg, &k_bob_to_alice).expect("Write failed");

            // Perform batch write
            s1.lock().unwrap().batch_write();

            let alice_read = alice
                .read(&k_bob_to_alice, "Bob".to_string(), 0)
                .expect("Read failed");
            assert_eq!(
                bob_msg, alice_read,
                "Read message doesn't match written message for bob"
            );

            let bob_read = bob
                .read(&k_alice_to_bob, "Alice".to_string(), 0)
                .expect("Read failed");
            assert_eq!(
                alice_msg, bob_read,
                "Read message doesn't match written message for alice"
            );
        }
    }

    #[test]
    fn test_read_old_message_single_client() {
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s1 = Arc::new(Mutex::new(Server1::new(s2.clone())));

        let mut alice: Client = Client::new("Alice".to_string(), s1.clone(), s2.clone());

        let mut rng = ChaCha20Rng::from_entropy();

        let key = Key::random(&mut rng);

        // Epoch 1: Alice writes
        s1.lock().unwrap().batch_init(1);

        alice.setup(&key).expect("Setup failed");

        let alice_msg_epoch1: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();

        alice.write(&alice_msg_epoch1, &key).expect("Write failed");

        s1.lock().unwrap().batch_write();

        let alice_read_epoch1: Vec<u8> = alice
            .read(&key, "Alice".to_string(), 0) // Read from epoch 1
            .expect("Read failed");

        assert_eq!(
            alice_msg_epoch1, alice_read_epoch1,
            "Read message doesn't match the written message from this epoch"
        );


        // Epoch 2: Alice writes again but reads the message from epoch 1
        s1.lock().unwrap().batch_init(1);

        let alice_msg_epoch2: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();

        alice.write(&alice_msg_epoch2, &key).expect("Write failed");

        s1.lock().unwrap().batch_write();

        // Alice reads from epoch 1
        let alice_read_epoch1: Vec<u8> = alice
            .read(&key, "Alice".to_string(), 1) // Read from epoch 1
            .expect("Read failed");

        assert_eq!(
            alice_msg_epoch1, alice_read_epoch1,
            "Read message doesn't match the written message from epoch 1"
        );
    }

    #[test]
    fn test_read_old_message_two_clients() {
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s1 = Arc::new(Mutex::new(Server1::new(s2.clone())));

        let mut alice: Client = Client::new("Alice".to_string(), s1.clone(), s2.clone());
        let mut bob: Client = Client::new("Bob".to_string(), s1.clone(), s2.clone());

        let mut rng = ChaCha20Rng::from_entropy();

        let key_alice_to_bob = Key::random(&mut rng);
        let key_bob_to_alice = Key::random(&mut rng);

        // Epoch 1: Alice and Bob write
        s1.lock().unwrap().batch_init(2);

        alice.setup(&key_alice_to_bob).expect("Alice setup failed");
        bob.setup(&key_alice_to_bob).expect("Bob setup failed");
        alice.setup(&key_bob_to_alice).expect("Alice setup failed");
        bob.setup(&key_bob_to_alice).expect("Bob setup failed");

        let alice_msg_epoch1: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
        alice.write(&alice_msg_epoch1, &key_alice_to_bob).expect("Alice write failed");

        let bob_msg_epoch1: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
        bob.write(&bob_msg_epoch1, &key_bob_to_alice).expect("Bob write failed");

        s1.lock().unwrap().batch_write();

        // Epoch 2: Alice and Bob write again
        s1.lock().unwrap().batch_init(2);

        let alice_msg_epoch2: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
        alice.write(&alice_msg_epoch2, &key_alice_to_bob).expect("Alice write failed in epoch 2");

        let bob_msg_epoch2: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
        bob.write(&bob_msg_epoch2, &key_bob_to_alice).expect("Bob write failed in epoch 2");

        s1.lock().unwrap().batch_write();

        let alice_read_epoch1: Vec<u8> = alice
            .read(&key_bob_to_alice, "Bob".to_string(), 1) // Read from epoch 1
            .expect("Alice read failed from epoch 1");

        let bob_read_epoch1: Vec<u8> = bob
            .read(&key_alice_to_bob, "Alice".to_string(), 1) // Bob reads Alice's message from epoch 1
            .expect("Bob read failed from epoch 1");

        assert_eq!(
            bob_msg_epoch1, alice_read_epoch1,
            "Alice: Read message doesn't match the written message from epoch 1"
        );

        assert_eq!(
            alice_msg_epoch1, bob_read_epoch1,
            "Bob: Read message doesn't match Alice's written message from epoch 1"
        );
    }

    #[test]
    fn test_read_old_message_single_client_multiple_epochs() {
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s1 = Arc::new(Mutex::new(Server1::new(s2.clone())));

        let mut alice: Client = Client::new("Alice".to_string(), s1.clone(), s2.clone());

        let mut rng = ChaCha20Rng::from_entropy();

        let key = Key::random(&mut rng);

        // Epoch 1: Alice writes
        s1.lock().unwrap().batch_init(1);

        alice.setup(&key).expect("Setup failed");

        let alice_msg_epoch1: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
        alice.write(&alice_msg_epoch1, &key).expect("Write failed");

        s1.lock().unwrap().batch_write();

        // Epoch 2: Alice writes again
        s1.lock().unwrap().batch_init(1);

        let alice_msg_epoch2: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
        alice.write(&alice_msg_epoch2, &key).expect("Write failed");

        s1.lock().unwrap().batch_write();

        // Alice reads from epoch 1
        let alice_read_epoch1_epoch2: Vec<u8> = alice
            .read(&key, "Alice".to_string(), 1) // Read from epoch 1
            .expect("Read failed in epoch 2");

        assert_eq!(
            alice_msg_epoch1, alice_read_epoch1_epoch2,
            "Read message doesn't match the written message from epoch 1 in epoch 2"
        );

        // Epoch 3: Alice writes again
        s1.lock().unwrap().batch_init(1);

        let alice_msg_epoch3: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
        alice.write(&alice_msg_epoch3, &key).expect("Write failed");

        s1.lock().unwrap().batch_write();

        // Alice reads from epoch 1 again
        let alice_read_epoch1_epoch3: Vec<u8> = alice
            .read(&key, "Alice".to_string(), 2) // Read from epoch 1
            .expect("Read failed in epoch 3");

        assert_eq!(
            alice_msg_epoch1, alice_read_epoch1_epoch3,
            "Read message doesn't match the written message from epoch 1 in epoch 3"
        );

        // Epoch 4: Alice writes again and reads from epoch 1
        s1.lock().unwrap().batch_init(1);

        let alice_msg_epoch4: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
        alice.write(&alice_msg_epoch4, &key).expect("Write failed");

        s1.lock().unwrap().batch_write();

        // Alice reads from epoch 1 again in epoch 4
        let alice_read_epoch1_epoch4: Vec<u8> = alice
            .read(&key, "Alice".to_string(), 3) // Read from epoch 1 in epoch 4
            .expect("Read failed in epoch 4");

        assert_eq!(
            alice_msg_epoch1, alice_read_epoch1_epoch4,
            "Read message doesn't match the written message from epoch 1 in epoch 4"
        );
    }

    #[test]
    #[cfg(feature = "simulation")]
    fn test_simulation() {
        use rand::{RngCore, SeedableRng};
        use rand_chacha::ChaCha20Rng;
        use std::time::Duration;
    
        let num_clients = NUM_WRITES_PER_EPOCH;
        let num_epochs = DELTA * DELTA;
    
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s1 = Arc::new(Mutex::new(Server1::new(s2.clone())));
    
        let mut rng = ChaCha20Rng::from_entropy();
        let mut clients = Vec::new();
        let mut keys = Vec::new();
    
        let mut total_duration: Duration = Duration::new(0, 0);
        let mut successful_epochs = 0;
    
        for i in 0..num_clients {
            let client_name = format!("Client_{}", i);
            let mut client = Client::new(client_name, s1.clone(), s2.clone());
    
            let key = Key::random(&mut rng);
            client.setup(&key).expect("Setup failed");
    
            clients.push(client);
            keys.push(key);
        }
    
        // Perform multiple epochs
        for epoch in 0..num_epochs {
            println!("Starting epoch: {}", epoch);
    
            // Measure batch_init latency
            let epoch_start_time = std::time::Instant::now();
            let batch_init_start_time = std::time::Instant::now();
            s1.lock().unwrap().batch_init(num_clients);
            let batch_init_duration = batch_init_start_time.elapsed();
    
            // Measure write latency
            let write_start_time = std::time::Instant::now();
            for (client, key) in clients.iter_mut().zip(keys.iter()) {
                let message: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
                if let Err(e) = client.write(&message, key) {
                    panic!("Write failed in epoch {}: {:?}", epoch, e);
                }
            }
            let write_duration = write_start_time.elapsed();
    
            // Measure batch_write latency
            let batch_write_start_time = std::time::Instant::now();
            s1.lock().unwrap().batch_write();
            let batch_write_duration = batch_write_start_time.elapsed();
    
            // Measure read latency for each client
            let mut total_read_duration = Duration::new(0, 0);
            for (client, key) in clients.iter().zip(keys.iter()) {
                let read_start_time = std::time::Instant::now();
                let read_result: Vec<u8> = client
                    .read(&key, client.id.clone(), 0)
                    .expect(&format!("Read failed in epoch {}", epoch));
                let client_read_duration = read_start_time.elapsed();
                total_read_duration += client_read_duration;
            }
    
            // Calculate average read duration across all clients in this epoch
            let average_read_duration = total_read_duration / num_clients as u32;
    
            // Measure total duration
            let epoch_duration = epoch_start_time.elapsed();
            total_duration += epoch_duration;
            successful_epochs += 1;
    
            // Print the duration of the current epoch and its phases
            println!(
                "Epoch {} completed in {:?} (batch_init: {:?}, write: {:?}, batch_write: {:?}, avg client read: {:?})",
                epoch, epoch_duration, batch_init_duration, write_duration, batch_write_duration, average_read_duration
            );
    
            // Calculate the average duration so far
            let average_duration = total_duration / successful_epochs as u32;
    
            // Print cumulative duration and average duration so far
            println!(
                "Total duration so far: {:?}, average duration so far: {:?}",
                total_duration, average_duration
            );
        }
    
        // After all epochs, print the total duration and final average duration
        let final_average_duration = total_duration / successful_epochs as u32;
        println!(
            "All epochs completed successfully. Total duration: {:?}, average duration: {:?}",
            total_duration, final_average_duration
        );
    }

    #[test]
    fn test_message_persistence() {
        let server2 = Arc::new(Mutex::new(Server2::new()));
        let server1 = Arc::new(Mutex::new(Server1::new(server2.clone())));

        let num_epochs = 20;
        let num_clients = 1;
        
        // Create a vector of unique messages and keys
        let mut rng = ChaCha20Rng::from_entropy();
        let messages: Vec<Vec<u8>> = (0..num_epochs)
            .map(|i| vec![i as u8, (i + 1) as u8, (i + 2) as u8, (i + 3) as u8])
            .collect();
        let keys: Vec<Key> = (0..num_epochs).map(|_| Key::random(&mut rng)).collect();
        let mut client = Client::new("Client".to_string(), server1.clone(), server2.clone());
        
        // Write messages
        for (epoch, (message, key)) in messages.iter().zip(keys.iter()).enumerate() {
            server1.lock().unwrap().batch_init(num_clients);

            client.setup(key).unwrap();
            client.write(message, key).unwrap();

            server1.lock().unwrap().batch_write().unwrap();
        }

        // Verify the messages
        let mut decrypted_messages = Vec::new();
        let _ = server2.lock().unwrap().tree
            .zip(&server1.lock().unwrap().metadata)
            .into_iter()
            .try_for_each(|(bucket, metadata_bucket, _path)| {
                let bucket = bucket.clone().ok_or(OramError::BucketNotFound)?;
                (0..bucket.len()).try_for_each(|b| {
                    metadata_bucket
                        .as_ref()
                        .ok_or(OramError::MetadataBucketNotFound)
                        .and_then(|metadata_bucket| {
                            let (_l, k_oram_t, t_exp) = metadata_bucket
                                .get(b)
                                .ok_or(OramError::MetadataIndexError(b))?;
                            if num_clients < (*t_exp as usize) {
                                let c_msg = bucket.get(b).ok_or(OramError::BucketIndexError(b))?;
                                if let Ok(ct) = decrypt(&k_oram_t.0, &c_msg.0) {
                                    // Use the correct k_msg for inner decryption
                                    for key in &keys {
                                        if let Some((k_msg, _, _)) = client.keys.get(key) {
                                            if let Ok(decrypted) = decrypt(k_msg, &ct) {
                                                decrypted_messages.push(trim_zeros(&decrypted));
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(())
                        })
                })
            });

        // Verify that all original messages are present in the decrypted messages
        let mut found_messages = 0;
        for original_msg in &messages {
            if decrypted_messages.contains(original_msg) {
                found_messages += 1;
            }
        }

        assert_eq!(found_messages, num_epochs * num_clients, 
            "Not all original messages were found in the decrypted messages");
        assert_eq!(decrypted_messages.len(), num_epochs * num_clients, 
            "Number of decrypted messages doesn't match the expected count");
    }

    #[test]
    fn test_message_movement() {
        let server2 = Arc::new(Mutex::new(Server2::new()));
        let server1 = Arc::new(Mutex::new(Server1::new(server2.clone())));

        let num_epochs = 1000;
        let mut rng = ChaCha20Rng::from_entropy();
        let key = Key::random(&mut rng);
        let message = vec![1, 2, 3, 4]; // Simple test message

        let mut client = Client::new("Client".to_string(), server1.clone(), server2.clone());
        client.setup(&key).expect("Client setup failed");

        // Initial write
        server1.lock().unwrap().batch_init(1);

        // Doing a client write manually and extracting the intended path of this message
        let epoch = client.epoch;
        let cs = client.id.clone().into_bytes();
        let (k_msg, k_oram, k_prf) = client.keys.get(&key).unwrap();
        let f: Vec<u8> = prf(k_prf, &epoch.to_be_bytes());
        let k_oram_t = kdf(k_oram, &epoch.to_string()).unwrap();
        let ct = encrypt(k_msg, &message, EncryptionType::Encrypt).unwrap();
        client.epoch += 1;
        client.s1.lock().unwrap().write(ct, f.clone(), Key::new(k_oram_t), cs.clone()).expect("Initial write failed");
        let k_s1_t = server1.lock().unwrap().k_s1_t.0.clone();
        let l = prf(k_s1_t.as_slice(), &[f.clone().as_slice(), cs.clone().as_slice()].concat());
        let intended_path = Path::from(l);

        server1.lock().unwrap().batch_write().expect("Initial batch write failed");

        let mut pathset: tree::SparseBinaryTree<Bucket> = server1.lock().unwrap().pt.clone();

        // Function to verify message at LCA
        let verify_message_at_lca = |lca_bucket: &Bucket, lca_path: &Path| {
            let metadata_bucket = server1.lock().unwrap().metadata.get(lca_path)
                .expect("Metadata not found at LCA");
            let mut found = false;
            for b in 0..lca_bucket.len() {
                let (l, k_oram_t, t_exp) = metadata_bucket
                    .get(b)
                    .ok_or(OramError::MetadataIndexError(b))
                    .expect("Failed to get metadata");
                let c_msg = lca_bucket.get(b)
                    .ok_or(OramError::BucketIndexError(b))
                    .expect("Failed to get bucket item");
                if let Ok(ct) = decrypt(&k_oram_t.0, &c_msg.0) {
                    if let Some((k_msg, _, _)) = client.keys.get(&key) {
                        if let Ok(decrypted) = decrypt(k_msg, &ct) {
                            let trimmed = trim_zeros(&decrypted);
                            if trimmed == message {
                                found = true;
                            }
                        }
                    }
                }
            }
            found
        };

        let (lca_bucket, lca_path) = pathset.lca(&intended_path)
        .expect("LCA not found");

        // Verify message at LCA
        assert!(verify_message_at_lca(&lca_bucket, &lca_path), 
        "Message not found at LCA in epoch {}", epoch);

        let mut latest_index = server2.lock().unwrap().tree.get_index(&lca_path);
        let mut times_relocated = 0;
        let mut lca_path_lengths = Vec::new();

        // Trace message movement over epochs
        for epoch in 1..num_epochs {

            // Perform batch_init
            server1.lock().unwrap().batch_init(1);

            // Perform batch_write
            server1.lock().unwrap().batch_write().expect("Batch write failed");

            let mut new_pathset: tree::SparseBinaryTree<Bucket> = server1.lock().unwrap().pt.clone();
            if new_pathset.packed_indices.contains(&latest_index) {
                let (lca_bucket, lca_path) = new_pathset.lca(&intended_path)
                .expect("LCA not found");

                let lca_path_length = lca_path.len();
                lca_path_lengths.push(lca_path_length);

                // Verify message at LCA
                assert!(verify_message_at_lca(&lca_bucket, &lca_path), 
                "Message not found at LCA in epoch {}", epoch);

                latest_index = new_pathset.get_index(&lca_path);
                times_relocated += 1;
            }
        }

        println!("Times relocated: {:?}", times_relocated);
        println!("LCA path lengths: {:?}", lca_path_lengths);
    }

}
