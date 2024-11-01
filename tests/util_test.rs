use myco_rs::{kdf, prf, encrypt, decrypt, trim_zeros, EncryptionType};
use myco_rs::dtypes::Key;
use myco_rs::constants::BLOCK_SIZE;
#[cfg(test)]
mod util_tests {
    use myco_rs::constants::INNER_BLOCK_SIZE;
    use rand::{seq::SliceRandom, thread_rng, RngCore, SeedableRng};

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

        let output1 = prf(key, input1).expect("PRF failed");
        let output2 = prf(key, input2).expect("PRF failed");

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
        let message_lengths: Vec<usize> = (0..INNER_BLOCK_SIZE).collect();

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

    use super::*;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_same_shuffle() {
        let seed: [u8; 32] = [0; 32];
        let mut rng1 = ChaCha20Rng::from_seed(seed);
        let mut rng2 = ChaCha20Rng::from_seed(seed);
        let mut v1 = (0..10).collect::<Vec<_>>();
        let mut v2 = v1.clone();
        v1.shuffle(&mut rng1);
        v2.shuffle(&mut rng2);
        assert_eq!(v1, v2);
    }
}