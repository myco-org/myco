#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_assignments)]
#![allow(unused_must_use)]
#![allow(dead_code)]
#![allow(unused_parens)]
#![allow(private_bounds)]

mod e2e_tests {
    use std::{
        fs::File,
        io::{Read, Write},
        sync::{Arc, Mutex},
    };

    use myco_rs::{
        client::Client,
        constants::{D, DELTA, NUM_CLIENTS, Z},
        decrypt,
        dtypes::{Bucket, Key, Metadata, Path},
        encrypt,
        error::OramError,
        kdf,
        logging::initialize_logging,
        network::{LocalServer1Access, LocalServer2Access},
        prf,
        server1::Server1,
        server2::Server2,
        tree::{self, deserialize_trees, serialize_trees, BinaryTree, DBStateParams},
        trim_zeros, EncryptionType,
    };
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

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
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(Mutex::new(Server1::new(s2_access.clone())));
        let s1_access = Box::new(LocalServer1Access { server: s1 });

        let mut alice = Client::new("Alice".to_string(), s1_access, s2_access.clone());

        let mut rng = ChaCha20Rng::from_entropy();
        let k = Key::random(&mut rng);
        alice.setup(&k).expect("Setup failed");
        assert!(alice.keys.contains_key(&k));
    }

    #[test]
    fn test_write_and_read() {
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(Mutex::new(Server1::new(s2_access.clone())));
        let s1_access = Box::new(LocalServer1Access { server: s1.clone() });
        let mut alice = Client::new("Alice".to_string(), s1_access, s2_access);

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
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(Mutex::new(Server1::new(s2_access)));

        let s2_access_alice = Box::new(LocalServer2Access { server: s2.clone() });

        let s1_access_alice = Box::new(LocalServer1Access { server: s1.clone() });
        let mut alice = Client::new("Alice".to_string(), s1_access_alice, s2_access_alice);

        let s2_access_bob = Box::new(LocalServer2Access { server: s2.clone() });
        let s1_access_bob = Box::new(LocalServer1Access { server: s1.clone() });
        let mut bob = Client::new("Bob".to_string(), s1_access_bob, s2_access_bob);

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
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(Mutex::new(Server1::new(s2_access.clone())));
        let s1_access = Box::new(LocalServer1Access { server: s1.clone() });
        let mut alice = Client::new("Alice".to_string(), s1_access, s2_access);

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
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(Mutex::new(Server1::new(s2_access)));

        let s2_access_alice = Box::new(LocalServer2Access { server: s2.clone() });
        let s1_access_alice = Box::new(LocalServer1Access { server: s1.clone() });
        let mut alice = Client::new("Alice".to_string(), s1_access_alice, s2_access_alice);

        let s2_access_bob = Box::new(LocalServer2Access { server: s2.clone() });
        let s1_access_bob = Box::new(LocalServer1Access { server: s1.clone() });
        let mut bob = Client::new("Bob".to_string(), s1_access_bob, s2_access_bob);

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
    fn test_read_old_message_single_client_single_epoch() {
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(Mutex::new(Server1::new(s2_access.clone())));
        let s1_access = Box::new(LocalServer1Access { server: s1.clone() });
        let mut alice = Client::new("Alice".to_string(), s1_access, s2_access);

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
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(Mutex::new(Server1::new(s2_access.clone())));
        let s1_access = Box::new(LocalServer1Access { server: s1.clone() });
        let mut alice = Client::new("Alice".to_string(), s1_access.clone(), s2_access.clone());

        let s2_access_bob = Box::new(LocalServer2Access { server: s2.clone() });
        let s1_access_bob = Box::new(LocalServer1Access { server: s1.clone() });
        let mut bob = Client::new(
            "Bob".to_string(),
            s1_access_bob.clone(),
            s2_access_bob.clone(),
        );

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
        alice
            .write(&alice_msg_epoch1, &key_alice_to_bob)
            .expect("Alice write failed");

        let bob_msg_epoch1: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
        bob.write(&bob_msg_epoch1, &key_bob_to_alice)
            .expect("Bob write failed");

        s1.lock().unwrap().batch_write();

        // Epoch 2: Alice and Bob write again
        s1.lock().unwrap().batch_init(2);

        let alice_msg_epoch2: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
        alice
            .write(&alice_msg_epoch2, &key_alice_to_bob)
            .expect("Alice write failed in epoch 2");

        let bob_msg_epoch2: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
        bob.write(&bob_msg_epoch2, &key_bob_to_alice)
            .expect("Bob write failed in epoch 2");

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
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(Mutex::new(Server1::new(s2_access.clone())));
        let s1_access = Box::new(LocalServer1Access { server: s1.clone() });
        let mut alice = Client::new("Alice".to_string(), s1_access, s2_access);

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

        // Epoch 3: Alice writes again and reads from epoch 1
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
    fn test_message_persistence() {
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(Mutex::new(Server1::new(s2_access.clone())));
        let s1_access = Box::new(LocalServer1Access { server: s1.clone() });

        let num_epochs = DELTA as usize;
        let num_clients = 1;

        // Create a vector of unique messages and keys
        let mut rng = ChaCha20Rng::from_entropy();
        let key = Key::random(&mut rng);
        let mut client = Client::new("Client".to_string(), s1_access, s2_access);
        client.setup(&key).unwrap();
        let k_msg = client.keys.get(&key).unwrap().0.clone();
        let mut messages = Vec::new();
        // Write messages
        for epoch in 0..num_epochs {
            s1.lock().unwrap().batch_init(num_clients);
            let message: Vec<u8> = (0..16).map(|_| (rng.next_u32() % 255 + 1) as u8).collect();
            client.write(&message, &key).unwrap();
            s1.lock().unwrap().batch_write().unwrap();
            messages.push(message);
        }

        // Verify the messages
        let mut decrypted_messages = Vec::new();
        let _ = s2
            .lock()
            .unwrap()
            .tree
            .zip(&s1.lock().unwrap().metadata)
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
                            let c_msg = bucket.get(b).ok_or(OramError::BucketIndexError(b))?;
                            if let Ok(ct) = decrypt(&k_oram_t.0, &c_msg.0) {
                                if let Ok(decrypted) = decrypt(&k_msg, &ct) {
                                    decrypted_messages.push(trim_zeros(&decrypted));
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
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(Mutex::new(Server1::new(s2_access.clone())));
        let s1_access = Box::new(LocalServer1Access { server: s1.clone() });
        let mut client = Client::new("Client".to_string(), s1_access, s2_access);

        let num_epochs = DELTA;
        let mut rng = ChaCha20Rng::from_entropy();
        let key = Key::random(&mut rng);
        let message = vec![1, 2, 3, 4]; // Simple test message

        // Initial write
        client.setup(&key).unwrap();
        s1.lock().unwrap().batch_init(1);

        // Doing a client write manually and extracting the intended path of this message
        let epoch = client.epoch;
        let cs = client.id.clone().into_bytes();
        let (k_msg, k_oram, k_prf) = client.keys.get(&key).unwrap();
        let f: Vec<u8> = prf(k_prf, &epoch.to_be_bytes()).expect("PRF failed");
        let k_oram_t = kdf(k_oram, &epoch.to_string()).expect("KDF failed");
        let ct = encrypt(k_msg, &message, EncryptionType::Encrypt).expect("Encryption failed");
        client.epoch += 1;
        client
            .s1
            .queue_write(ct, f.clone(), Key::new(k_oram_t), cs.clone())
            .await
            .expect("Initial write failed");
        let k_s1_t = s1.lock().unwrap().k_s1_t.0.clone();
        let l = prf(
            k_s1_t.as_slice(),
            &[f.clone().as_slice(), cs.clone().as_slice()].concat(),
        )
        .expect("PRF failed");
        let intended_path = Path::from(l);

        s1.lock()
            .unwrap()
            .batch_write()
            .expect("Initial batch write failed");

        let mut pathset: tree::SparseBinaryTree<Bucket> = s1.lock().unwrap().pt.clone();

        // Function to verify message at LCA
        let verify_message_at_lca = |lca_bucket: &Bucket, lca_path: &Path| {
            let metadata_bucket = s1
                .lock()
                .unwrap()
                .metadata
                .get(lca_path)
                .expect("Metadata not found at LCA");
            let mut found = false;
            for b in 0..lca_bucket.len() {
                let (l, k_oram_t, t_exp) = metadata_bucket
                    .get(b)
                    .ok_or(OramError::MetadataIndexError(b))
                    .expect("Failed to get metadata");
                let c_msg = lca_bucket
                    .get(b)
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

        let (lca_bucket, lca_path) = pathset.lca(&intended_path).expect("LCA not found");

        // Verify message at LCA
        assert!(
            verify_message_at_lca(&lca_bucket, &lca_path),
            "Message not found at LCA in epoch {}",
            epoch
        );

        let mut latest_index = s2.lock().unwrap().tree.get_index(&lca_path);
        let mut times_relocated = 0;
        let mut lca_path_lengths = Vec::new();

        // Trace message movement over epochs
        for epoch in 1..num_epochs {
            // Perform batch_init
            s1.lock().unwrap().batch_init(1);

            // Perform batch_write
            s1.lock()
                .unwrap()
                .batch_write()
                .expect("Batch write failed");

            let mut new_pathset: tree::SparseBinaryTree<Bucket> = s1.lock().unwrap().pt.clone();
            if new_pathset.packed_indices.contains(&latest_index) {
                let (lca_bucket, lca_path) =
                    new_pathset.lca(&intended_path).expect("LCA not found");

                let lca_path_length = lca_path.len();
                lca_path_lengths.push(lca_path_length);

                // Verify message at LCA
                assert!(
                    verify_message_at_lca(&lca_bucket, &lca_path),
                    "Message not found at LCA in epoch {}",
                    epoch
                );

                latest_index = new_pathset.get_index(&lca_path);
                times_relocated += 1;
            }
        }

        println!("Times relocated: {:?}", times_relocated);
        println!("LCA path lengths: {:?}", lca_path_lengths);
    }

    #[test]
    /// Tests the serialization and deserialization of the server 2 tree and the server 1 metadata tree.
    fn test_tree_serialization() {
        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(Mutex::new(Server1::new(s2_access.clone())));

        let s1_metadata_serialized = bincode::serialize(&s1.lock().unwrap().metadata).unwrap();
        let s1_metadata_deserialized: BinaryTree<Metadata> =
            bincode::deserialize(&s1_metadata_serialized).unwrap();

        let s2_tree_serialized = bincode::serialize(&s2.lock().unwrap().tree).unwrap();
        let s2_tree_deserialized: BinaryTree<Bucket> =
            bincode::deserialize(&s2_tree_serialized).unwrap();

        assert_eq!(s1.lock().unwrap().metadata, s1_metadata_deserialized);
        assert_eq!(s2.lock().unwrap().tree, s2_tree_deserialized);
    }

    /// Helper function to test the execution of the protocol over a user-defined number of clients and epochs.
    fn test_protocol_execution_with_params(
        s1: Arc<Mutex<Server1>>,
        s2: Arc<Mutex<Server2>>,
        num_clients: usize,
        num_epochs: usize,
    ) {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut clients: Vec<Client> = Vec::new();

        let mut k_msg: Vec<u8> = Vec::new();
        let key = Key::random(&mut rng);
        for i in 0..num_clients {
            let client_name = format!("Client_{}", i);
            let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
            let s1_access = Box::new(LocalServer1Access { server: s1.clone() });
            let mut client = Client::new(client_name, s1_access, s2_access);

            client.setup(&key).expect("Setup failed");
            clients.push(client);
        }
        k_msg = clients[0].keys.get(&key).unwrap().0.clone();

        // Perform multiple epochs
        for epoch in 0..num_epochs {
            println!("Starting epoch: {}", epoch);

            s1.lock().unwrap().batch_init(num_clients);

            for client in clients.iter_mut() {
                let message: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
                if let Err(e) = client.write(&message, &key) {
                    panic!("Write failed in epoch {}: {:?}", epoch, e);
                }
            }

            s1.lock().unwrap().batch_write();

            for client in clients.iter() {
                let _: Vec<u8> = client
                    .read(&key, client.id.clone(), 0)
                    .expect(&format!("Read failed in epoch {}", epoch));
            }
        }
    }

    #[test]
    #[cfg(feature = "simulation")]
    /// Tests the execution of the protocol, then serializes the protocol mid-execution, serializes it and reloads it back into S1 and S2.
    fn test_create_serialized_full_db() {
        use super::*;

        let num_clients = NUM_CLIENTS;
        let num_epochs = 15;

        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(Mutex::new(Server1::new(s2_access)));

        test_protocol_execution_with_params(
            s1.clone(),
            s2.clone(),
            num_clients,
            num_epochs as usize,
        );

        let state_params = DBStateParams {
            bucket_size: Z,
            num_iters: DELTA as usize,
            depth: D,
            num_clients: NUM_CLIENTS,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
        };

        serialize_trees(
            &s2.lock().unwrap().tree,
            &s1.lock().unwrap().metadata,
            &state_params,
        );

        let (server2_tree_deserialized, server1_metadata_deserialized) =
            deserialize_trees(&state_params);

        // Assert that the deserialized server 1 metadata and the server 2 tree are the same as the original ones.
        assert_eq!(s1.lock().unwrap().metadata, server1_metadata_deserialized);
        assert_eq!(s2.lock().unwrap().tree, server2_tree_deserialized);

        s1.lock().unwrap().metadata = server1_metadata_deserialized;
        s2.lock().unwrap().tree = server2_tree_deserialized;

        test_protocol_execution_with_params(s1, s2, num_clients, num_epochs as usize);
    }

    #[test]
    fn test_batch_write_logging() {
        // Initialize logging first
        #[cfg(feature = "perf-logging")]
        initialize_logging("server1_latency.csv", "server1_bytes.csv");

        let s2 = Arc::new(Mutex::new(Server2::new()));
        let s2_access = Box::new(LocalServer2Access { server: s2.clone() });
        let s1 = Arc::new(Mutex::new(Server1::new(s2_access.clone())));

        // Do a batch init and write to generate metrics
        s1.lock().unwrap().batch_init(1);
        let result = s1.lock().unwrap().batch_write();
        assert!(result.is_ok(), "Batch write failed");

        // Verify log files exist in the latency_logs directory
        #[cfg(feature = "perf-logging")]
        {
            assert!(
                std::path::Path::new("latency_logs/server1_latency.csv").exists(),
                "Latency log file not found"
            );
            assert!(
                std::path::Path::new("latency_logs/server1_bytes.csv").exists(),
                "Bytes log file not found"
            );
        }
    }
}
