mod myco_tests {
    use std::{collections::HashMap, sync::Arc};
    use tokio::sync::RwLock;
    use myco::{client::Keys, constants::{DELTA, MESSAGE_SIZE}, crypto::{decrypt, decrypt_with_aad, encrypt_with_aad, kdf, prf, prf_fixed_length}, dtypes::{Bucket, Key}, utils::trim_zeros};
    use myco::{
        client::Client, constants::LAMBDA_BYTES, dtypes::Path, network::{server1::LocalServer1Access, server2::LocalServer2Access}, server1::Server1, server2::Server2,
    };
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[tokio::test]
    async fn test_client_setup() {
        let s2 = Arc::new(RwLock::new(Server2::new(1)));
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(RwLock::new(Server1::new(s2_access.clone(), 1)));
        let s1_access = Box::new(LocalServer1Access { server: s1.clone() });

        let mut alice = Client::new("Alice".to_string(), s1_access, s2_access.clone(), 1);

        let mut rng = ChaCha20Rng::from_entropy();
        let k = Key::random(&mut rng);
        alice.setup(vec![k.clone()], vec!["Alice".to_string()]).expect("Setup failed");
        assert!(alice.sending_keys.contains_key("Alice"));
        assert!(alice.receiving_keys.contains_key("Alice"));
    }

    #[tokio::test]
    async fn test_write_and_read() {
        let s2 = Arc::new(RwLock::new(Server2::new(1)));
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(RwLock::new(Server1::new(s2_access.clone(), 1)));
        let s1_access = Box::new(LocalServer1Access { server: s1.clone() });
        let mut alice = Client::new("Alice".to_string(), s1_access, s2_access, 1);
        let mut rng = ChaCha20Rng::from_entropy();
        let k = Key::random(&mut rng);
        alice.setup(vec![k.clone()], vec!["Alice".to_string()]).expect("Setup failed");
        let _ = s1.write().await.batch_init();
        alice.write(&[1u8], "Alice").unwrap();
        let _ = s1.write().await.batch_write();
        let msg = alice.read(Some(1)).unwrap();
        assert_eq!(msg, vec![1u8]);
    }

    #[tokio::test]
    async fn test_multiple_clients_one_epoch() {
        let num_clients = 2;

        let s2 = Arc::new(RwLock::new(Server2::new(num_clients)));
        let s2_access_shared = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(RwLock::new(Server1::new(s2_access_shared.clone(), num_clients)));

        let s2_access_alice = Box::new(LocalServer2Access { server: s2.clone() });
        let s1_access_alice = Box::new(LocalServer1Access { server: s1.clone() });
        let mut alice = Client::new("Alice".to_string(), s1_access_alice, s2_access_alice, num_clients);

        let s2_access_bob = Box::new(LocalServer2Access { server: s2.clone() });
        let s1_access_bob = Box::new(LocalServer1Access { server: s1.clone() });
        let mut bob = Client::new("Bob".to_string(), s1_access_bob, s2_access_bob, num_clients);

        let mut rng = ChaCha20Rng::from_entropy();
        let k = Key::random(&mut rng);

        alice.setup(vec![k.clone()], vec!["Bob".to_string()]).expect("Alice setup failed");
        bob.setup(vec![k.clone()], vec!["Alice".to_string()]).expect("Bob setup failed");

        let _ = s1.write().await.batch_init();

        alice.write(&[1u8], "Bob").unwrap();
        bob.write(&[2u8], "Alice").unwrap();

        let _ = s1.write().await.batch_write();

        let msg_for_alice = alice.read(Some(1)).unwrap();
        assert_eq!(msg_for_alice, vec![2u8]);

        let msg_for_bob = bob.read(Some(1)).unwrap();
        assert_eq!(msg_for_bob, vec![1u8]);
    }

    #[tokio::test]
    async fn test_multiple_writes_and_reads() {
        let s2 = Arc::new(RwLock::new(Server2::new(1)));
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(RwLock::new(Server1::new(s2_access.clone(), 1)));
        let s1_access = Box::new(LocalServer1Access { server: s1.clone() });
        let mut alice = Client::new("Alice".to_string(), s1_access, s2_access, 1);

        let num_operations = 5;
        for i in 0..num_operations {
            let mut rng = ChaCha20Rng::from_entropy();
            let key = Key::random(&mut rng);
            let msg = vec![i as u8, (i + 1) as u8, (i + 2) as u8];

            alice.setup(vec![key.clone()], vec!["Alice".to_string()]).expect("Setup failed");

            let _ = s1.write().await.batch_init();

            alice.write(&msg, "Alice").unwrap();

            let _ = s1.write().await.batch_write();

            let read_msg = alice.read(Some(1)).unwrap();
            assert_eq!(read_msg, msg, "Mismatch for operation {}", i);
        }
    }

    #[tokio::test]
    async fn test_multiple_clients_multiple_epochs() {
        let num_clients = 2;

        let s2 = Arc::new(RwLock::new(Server2::new(num_clients)));
        let s2_access_shared = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(RwLock::new(Server1::new(s2_access_shared.clone(), num_clients)));

        let s2_access_alice = Box::new(LocalServer2Access { server: s2.clone() });
        let s1_access_alice = Box::new(LocalServer1Access { server: s1.clone() });
        let mut alice = Client::new("Alice".to_string(), s1_access_alice, s2_access_alice, num_clients);

        let s2_access_bob = Box::new(LocalServer2Access { server: s2.clone() });
        let s1_access_bob = Box::new(LocalServer1Access { server: s1.clone() });
        let mut bob = Client::new("Bob".to_string(), s1_access_bob, s2_access_bob, num_clients);

        let mut rng = ChaCha20Rng::from_entropy();
        for _ in 0..5 {
            let _ = s1.write().await.batch_init();

            let k = Key::random(&mut rng);

            alice.setup(
                vec![k.clone()],
                vec!["Bob".to_string()],
            ).expect("Alice setup failed");
            bob.setup(
                vec![k.clone()],
                vec!["Alice".to_string()],
            ).expect("Bob setup failed");

            let alice_msg: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
            let bob_msg: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();

            alice.write(&alice_msg, "Bob").unwrap();
            bob.write(&bob_msg, "Alice").unwrap();

            let _ = s1.write().await.batch_write();

            let alice_read = alice.read(Some(1)).unwrap();
            assert_eq!(
                alice_read, bob_msg,
                "Alice: Read message doesn't match Bob's message"
            );

            let bob_read = bob.read(Some(1)).unwrap();
            assert_eq!(
                bob_read, alice_msg,
                "Bob: Read message doesn't match Alice's message"
            );
        }
    }

    #[tokio::test]
    async fn test_read_old_message_single_client_single_epoch() {
        let s2 = Arc::new(RwLock::new(Server2::new(1)));
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(RwLock::new(Server1::new(s2_access.clone(), 1)));
        let s1_access = Box::new(LocalServer1Access { server: s1.clone() });
        let mut alice = Client::new("Alice".to_string(), s1_access, s2_access, 1);

        let mut rng = ChaCha20Rng::from_entropy();
        let key = Key::random(&mut rng);
        alice.setup(vec![key.clone()], vec!["Alice".to_string()]).expect("Setup failed");

        // Alice writes but does not read in epoch 1
        let _ = s1.write().await.batch_init();
        let alice_msg_epoch1: Vec<u8> =
            (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
        alice.write(&alice_msg_epoch1, "Alice").unwrap();
        let _ = s1.write().await.batch_write();

        // Alice writes again in epoch 2
        let _ = s1.write().await.batch_init();
        let alice_msg_epoch2: Vec<u8> =
            (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
        alice.write(&alice_msg_epoch2, "Alice").unwrap();
        let _ = s1.write().await.batch_write();

        // Alice reads the message from epoch 1
        let alice_read: Vec<u8> =
            alice.read(Some(2)).unwrap();
        assert!(
            alice_read == alice_msg_epoch1 || alice_read == alice_msg_epoch2,
            "Old message read does not match either the epoch 1 or epoch 2 message"
        );
    }

    #[tokio::test]
    async fn test_read_old_message_two_clients() {
        let s2 = Arc::new(RwLock::new(Server2::new(2)));
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(RwLock::new(Server1::new(s2_access.clone(), 2)));
        let s1_access = Box::new(LocalServer1Access { server: s1.clone() });
        let mut alice = Client::new("Alice".to_string(), s1_access.clone(), s2_access.clone(), 2);

        let s1_access_bob = Box::new(LocalServer1Access { server: s1.clone() });
        let s2_access_bob = Box::new(LocalServer2Access { server: s2.clone() });
        let mut bob = Client::new("Bob".to_string(), s1_access_bob, s2_access_bob, 2);

        let mut rng = ChaCha20Rng::from_entropy();
        let key = Key::random(&mut rng);

        let _ = s1.write().await.batch_init();
        alice.setup(
            vec![key.clone()],
            vec!["Bob".to_string()],
        ).expect("Alice setup failed");
        bob.setup(
            vec![key.clone()],
            vec!["Alice".to_string()],
        ).expect("Bob setup failed");

        let alice_msg_epoch1: Vec<u8> =
            (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
        alice.write(&alice_msg_epoch1, "Bob").unwrap();

        let bob_msg_epoch1: Vec<u8> =
            (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
        bob.write(&bob_msg_epoch1, "Alice").unwrap();

        let _ = s1.write().await.batch_write();

        let alice_read_epoch1: Vec<u8> =
            alice.read(Some(1)).unwrap();
        let bob_read_epoch1: Vec<u8> =
            bob.read(Some(1)).unwrap();

        assert_eq!(
            bob_msg_epoch1, alice_read_epoch1,
            "Alice: Read message doesn't match the written message from epoch 1"
        );
        assert_eq!(
            alice_msg_epoch1, bob_read_epoch1,
            "Bob: Read message doesn't match the written message from epoch 1"
        );
    }

    #[tokio::test]
    async fn test_message_persistence() {
        let num_clients = 1;
        let s2 = Arc::new(RwLock::new(Server2::new(num_clients)));
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(RwLock::new(Server1::new(s2_access.clone(), num_clients)));
        let s1_access = Box::new(LocalServer1Access { server: s1.clone() });

        let num_epochs = DELTA;

        // Create a vector of unique messages and keys
        let mut rng = ChaCha20Rng::from_entropy();
        let key = Key::random(&mut rng);
        let mut client = Client::new("Client".to_string(), s1_access, s2_access, 1);
        client.setup(vec![key.clone()], vec!["Client".to_string()]).unwrap();
        let k_enc = client.sending_keys.get("Client").unwrap().k_enc.bytes.clone();
        let mut messages = Vec::new();
        // Write messages
        for _ in 0..num_epochs {
            let _ = s1.write().await.batch_init();
            let message: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
            client.write(&message, "Client").unwrap();
            let _ = s1.write().await.batch_write();
            messages.push(message);
        }

        // Verify the messages
        let mut decrypted_messages = Vec::new();
        let s2_guard = s2.read().await;
        let s1_guard = s1.read().await;
        // Server1 keeps, for every bucket, the messages it holds with their keys. Each of those
        // blocks must be in the same bucket of Server2's tree and decrypt to a written message.
        for (index, bucket_opt) in s2_guard.tree.value.iter().enumerate().skip(1) {
            let bucket = bucket_opt.clone().unwrap();
            for held in s1_guard.held_in_bucket(index) {
                assert!(
                    bucket.iter().any(|block| block.0 == held.block),
                    "Server2's bucket {} does not contain a block that Server1 holds for it",
                    index
                );
                if let Ok(ct) = decrypt(&held.key.bytes, &held.block) {
                    // The inner layer is bound to the epoch the message was written in.
                    if let Some(decrypted) = (0..num_epochs).find_map(|t| decrypt_with_aad(&k_enc, &ct, &(t as u64).to_be_bytes()).ok()) {
                        decrypted_messages.push(trim_zeros(&decrypted));
                    }
                }
            }
        }

        // Verify that all original messages are present in the decrypted messages
        let mut found_messages = 0;
        for original_msg in &messages {
            if decrypted_messages.contains(original_msg) {
                found_messages += 1;
            }
        }

        assert_eq!(
            found_messages,
            num_epochs * num_clients,
            "Not all original messages were found in the decrypted messages"
        );
        assert_eq!(
            decrypted_messages.len(),
            num_epochs * num_clients,
            "Number of decrypted messages doesn't match the expected count"
        );
    }

    #[tokio::test]
    async fn test_message_movement() {
        let s2 = Arc::new(RwLock::new(Server2::new(1)));
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(RwLock::new(Server1::new(s2_access.clone(), 1)));
        let s1_access = Box::new(LocalServer1Access { server: s1.clone() });
        let mut client = Client::new("Client".to_string(), s1_access, s2_access, 1);

        let mut rng = ChaCha20Rng::from_entropy();
        let key = Key::random(&mut rng);
        let message = vec![1, 2, 3, 4]; // Simple test message

        // Initial write
        client.setup(vec![key.clone()], vec!["Client".to_string()]).unwrap();
        let _ = s1.write().await.batch_init();

        // Doing a client write manually and extracting the intended path of this message
        let epoch = client.epoch;
        let c_s = client.id.clone().into_bytes();
        let keys = client.sending_keys.get("Client").unwrap();
        let f = prf(keys.k_rk.bytes.as_slice(), &epoch.to_be_bytes()).expect("PRF failed");
        let f_ntf = prf(keys.k_rk_ntf.bytes.as_slice(), &epoch.to_be_bytes()).expect("PRF failed");
        let k_renc_t = kdf(keys.k_renc.bytes.as_slice(), &epoch.to_string()).expect("KDF failed");
        let ct = encrypt_with_aad(keys.k_enc.bytes.as_slice(), &message, MESSAGE_SIZE, &(epoch as u64).to_be_bytes()).expect("Encryption failed");
        let ct_ntf = prf_fixed_length(keys.k_ntf.bytes.as_slice(), epoch.to_be_bytes().as_slice(), LAMBDA_BYTES).expect("PRF failed");
        client.epoch += 1;
        client
            .s1
            .queue_write(ct, ct_ntf, f.clone(), f_ntf.clone(), Key::new(k_renc_t), c_s.clone())
            .await
            .expect("Initial write failed");
        let k_s1_t = s1.read().await.k_s1_t.bytes.clone();
        let l = myco::utils::tree_location(k_s1_t.as_slice(), &f, &c_s).expect("PRF failed");
        let intended_path = Path::from(l);

        let _ = s1.write().await.batch_write();

        // The message must be in the deepest bucket of the epoch's path set on its intended path.
        let lca_index = s1.read().await.pathset().deepest_on(&intended_path);

        // Verify message at LCA using the free async function
        assert!(
            verify_message_at_lca(s1.clone(), s2.clone(), client.receiving_keys.clone(), lca_index, message.clone()).await,
            "Message not found at LCA in epoch {}",
            epoch
        );

        let mut latest_index = lca_index;
        let mut times_relocated = 0;
        let mut lca_path_lengths = Vec::new();

        // Trace message movement over epochs
        for epoch in 1..DELTA {
            {
                let mut s1_guard = s1.write().await;
                s1_guard.batch_init().expect("Batch init failed");
                s1_guard.batch_write().expect("Batch write failed");
            }

            let (in_pathset, lca_index) = {
                let s1_guard = s1.read().await;
                (s1_guard.pathset().contains(latest_index), s1_guard.pathset().deepest_on(&intended_path))
            };
            if in_pathset {
                // The path from the root to a bucket has as many steps as the bucket's depth.
                let lca_path_length = lca_index.ilog2() as usize;
                lca_path_lengths.push(lca_path_length);
                // Verify message at LCA using the free async function
                assert!(
                    verify_message_at_lca(s1.clone(), s2.clone(), client.receiving_keys.clone(), lca_index, message.clone()).await,
                    "Message not found at LCA in epoch {}",
                    epoch
                );
                latest_index = lca_index;
                times_relocated += 1;
            } else {
                // A bucket outside the path set is not rewritten: the message stays where it is.
                assert!(
                    verify_message_at_lca(s1.clone(), s2.clone(), client.receiving_keys.clone(), latest_index, message.clone()).await,
                    "Message not found in its bucket in epoch {}",
                    epoch
                );
            }
        }

        println!("Times relocated: {:?}", times_relocated);
        println!("LCA path lengths: {:?}", lca_path_lengths);
    }

    #[tokio::test]
    async fn test_no_notifications() {
        let s2 = Arc::new(RwLock::new(Server2::new(1)));
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(RwLock::new(Server1::new(s2_access.clone(), 1)));
        let s1_access = Box::new(LocalServer1Access { server: s1.clone() });
        let mut client = Client::new("TestClient".to_string(), s1_access, s2_access, 1);

        let mut rng = ChaCha20Rng::from_entropy();
        let key = Key::random(&mut rng);
        client.setup(vec![key], vec!["TestClient".to_string()]).unwrap();

        let _ = s1.write().await.batch_init();
        let _ = s1.write().await.batch_write();

        // Note: No write operations are performed here, so no notifications should be generated.
        let read_result = client.read(Some(1));
        assert!(read_result.is_ok(), "Fake read should succeed even with no notifications.");
        let message = read_result.unwrap();
        assert_eq!(message, vec![], "Fake read should return an empty message.");
    }

    #[tokio::test]
    async fn test_write_read_across_delta_plus_one_epochs() {
        let num_clients = 1;
        let s2 = Arc::new(RwLock::new(Server2::new(num_clients)));
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(RwLock::new(Server1::new(s2_access.clone(), num_clients)));
        let s1_access = Box::new(LocalServer1Access { server: s1.clone() });
        let mut client = Client::new("Client".to_string(), s1_access, s2_access, num_clients);

        let mut rng = ChaCha20Rng::from_entropy();
        let key = Key::random(&mut rng);
        client.setup(vec![key.clone()], vec!["Client".to_string()]).expect("Setup failed");
        
        // Create a consistent message to use across all epochs
        let original_message: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
        
        // Perform write and read operations for DELTA+1 epochs
        for epoch in 0..DELTA+10 {
            // Initialize the batch for this epoch
            let _ = s1.write().await.batch_init();
            
            // Write the same message in each epoch
            client.write(&original_message, "Client").unwrap();
            
            // Write the batch
            let _ = s1.write().await.batch_write();
            
            // Read the message
            let read_message = client.read(Some(1)).unwrap();

            println!("Read message: {:?}", read_message);
            
            // Verify that the read message matches the original message
            assert_eq!(
                read_message, 
                original_message,
                "Epoch {}: Read message doesn't match the original message", 
                epoch
            );
            
            println!("Epoch {}: Message successfully written and read", epoch);
        }
        
        println!("Successfully completed write-read operations across {} epochs", DELTA+10);
    }

    /// Whether the bucket with tree index `lca_index` holds `message`: Server1 must hold a key
    /// for it there, and the block it holds must be one of the blocks in Server2's bucket.
    async fn verify_message_at_lca(
        s1: Arc<RwLock<Server1>>,
        s2: Arc<RwLock<Server2>>,
        receiving_keys: HashMap<String, Keys>,
        lca_index: usize,
        message: Vec<u8>,
    ) -> bool {
        let held_messages = s1.read().await.held_in_bucket(lca_index);
        let lca_bucket: Bucket = s2.read().await.tree.value[lca_index].clone().expect("Bucket not found at LCA");
        let mut found = false;
        for held in held_messages {
            if !lca_bucket.iter().any(|block| block.0 == held.block) {
                continue;
            }
            if let Ok(ct) = decrypt(&held.key.bytes, &held.block) {
                if let Some(keys) = receiving_keys.get("Client") {
                    // The message was written in epoch 0.
                    if let Ok(decrypted) = decrypt_with_aad(keys.k_enc.bytes.as_slice(), &ct, &0u64.to_be_bytes()) {
                        if trim_zeros(&decrypted) == message.as_slice() {
                            found = true;
                        }
                    }
                }
            }
        }
        found
    }
}