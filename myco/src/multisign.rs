//! Signing several buckets at once.
//!
//! An Ed25519 signature hashes its message twice with SHA-512, and for a bucket that is nearly
//! all of the cost of signing. SHA-512 works on 64-bit words, so a 512-bit vector register can
//! carry eight independent hashes side by side (four in a 256-bit register). This module
//! computes the two hashes of several equally long messages in such lanes and assembles the
//! signatures from them.
//!
//! The signatures are byte-for-byte the ones [`crate::crypto::sign`] produces for the same
//! messages: Ed25519 is deterministic, and nothing about what is hashed or how the signature is
//! derived changes.
//!
//! The lane code is ordinary Rust on arrays of `u64`. Compiled for a CPU with the wider
//! registers, the same source becomes vector code; the lane count is chosen at run time from
//! what the CPU supports.

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{ExpandedSecretKey, PublicKey, SecretKey, SIGNATURE_LENGTH};
use lazy_static::lazy_static;

use crate::constants::SERVER_SIGNING_SEED;

const BLOCK: usize = 128;

const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

const IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// The SHA-512 of `N` equally long messages, written once and compiled for each kind of lane.
///
/// The module that invokes this defines the lane type `V` (one 64-bit word of each of `N`
/// hashes) and its operations: `splat`, `from_words`, `to_words`, `add`, `xor`, `rotr`, `shr`,
/// `ch` and `maj`. The attributes passed in are put on the generated functions.
macro_rules! sha512_lanes_impl {
    ($(#[$attr:meta])*) => {
        /// The SHA-512 compression function on `N` hashes at once. `blocks[lane]` is the next
        /// 128-byte block of hash `lane`.
        $(#[$attr])*
        unsafe fn compress(state: &mut [V; 8], blocks: &[&[u8]; N]) {
            let mut w = [splat(0); 16];
            for t in 0..16 {
                let mut words = [0u64; N];
                for lane in 0..N {
                    words[lane] = u64::from_be_bytes(blocks[lane][8 * t..8 * t + 8].try_into().unwrap());
                }
                w[t] = from_words(words);
            }

            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
            for t in 0..80 {
                if t >= 16 {
                    let w15 = w[(t + 1) & 15];
                    let w2 = w[(t + 14) & 15];
                    let s0 = xor(xor(rotr(w15, 1), rotr(w15, 8)), shr(w15, 7));
                    let s1 = xor(xor(rotr(w2, 19), rotr(w2, 61)), shr(w2, 6));
                    w[t & 15] = add(add(add(w[t & 15], s0), w[(t + 9) & 15]), s1);
                }
                let big_s1 = xor(xor(rotr(e, 14), rotr(e, 18)), rotr(e, 41));
                let t1 = add(add(add(add(h, big_s1), ch(e, f, g)), splat(super::K[t])), w[t & 15]);
                let big_s0 = xor(xor(rotr(a, 28), rotr(a, 34)), rotr(a, 39));
                let t2 = add(big_s0, maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = add(d, t1);
                d = c;
                c = b;
                b = a;
                a = add(t1, t2);
            }
            let after = [a, b, c, d, e, f, g, h];
            for i in 0..8 {
                state[i] = add(state[i], after[i]);
            }
        }

        /// SHA-512 of `N` messages of the same length.
        $(#[$attr])*
        pub(super) unsafe fn hash(messages: &[&[u8]; N]) -> [[u8; 64]; N] {
            const BLOCK: usize = super::BLOCK;
            let len = messages[0].len();
            assert!(messages.iter().all(|message| message.len() == len), "Messages hashed together must have the same length");

            let mut state = [splat(0); 8];
            for i in 0..8 {
                state[i] = splat(super::IV[i]);
            }
            let whole_blocks = len / BLOCK;
            for block in 0..whole_blocks {
                let blocks: [&[u8]; N] = std::array::from_fn(|lane| &messages[lane][block * BLOCK..(block + 1) * BLOCK]);
                compress(&mut state, &blocks);
            }

            // The rest of each message, the padding bit, zeros and the length in bits: one or two blocks.
            let rest = len - whole_blocks * BLOCK;
            let tail_blocks = if rest + 1 + 16 <= BLOCK { 1 } else { 2 };
            let mut tails = [[0u8; 2 * BLOCK]; N];
            for lane in 0..N {
                tails[lane][..rest].copy_from_slice(&messages[lane][whole_blocks * BLOCK..]);
                tails[lane][rest] = 0x80;
                tails[lane][tail_blocks * BLOCK - 16..tail_blocks * BLOCK].copy_from_slice(&((len as u128) * 8).to_be_bytes());
            }
            for block in 0..tail_blocks {
                let blocks: [&[u8]; N] = std::array::from_fn(|lane| &tails[lane][block * BLOCK..(block + 1) * BLOCK]);
                compress(&mut state, &blocks);
            }

            let mut digests = [[0u8; 64]; N];
            for i in 0..8 {
                let words = to_words(state[i]);
                for lane in 0..N {
                    digests[lane][8 * i..8 * i + 8].copy_from_slice(&words[lane].to_be_bytes());
                }
            }
            digests
        }
    };
}

/// One hash at a time, in plain 64-bit arithmetic. Runs on any CPU; the reference the vector
/// versions are checked against.
mod portable {
    pub(super) const N: usize = 1;
    type V = u64;
    #[inline(always)]
    fn splat(value: u64) -> V {
        value
    }
    #[inline(always)]
    fn from_words(words: [u64; N]) -> V {
        words[0]
    }
    #[inline(always)]
    fn to_words(v: V) -> [u64; N] {
        [v]
    }
    #[inline(always)]
    fn add(a: V, b: V) -> V {
        a.wrapping_add(b)
    }
    #[inline(always)]
    fn xor(a: V, b: V) -> V {
        a ^ b
    }
    #[inline(always)]
    fn rotr(a: V, bits: u32) -> V {
        a.rotate_right(bits)
    }
    #[inline(always)]
    fn shr(a: V, bits: u32) -> V {
        a >> bits
    }
    #[inline(always)]
    fn ch(e: V, f: V, g: V) -> V {
        (e & f) ^ (!e & g)
    }
    #[inline(always)]
    fn maj(a: V, b: V, c: V) -> V {
        (a & b) ^ (a & c) ^ (b & c)
    }
    sha512_lanes_impl!();
}

/// Four hashes at a time in 256-bit registers.
#[cfg(target_arch = "x86_64")]
mod avx2 {
    use std::arch::x86_64::*;
    pub(super) const N: usize = 4;
    type V = __m256i;
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn splat(value: u64) -> V {
        _mm256_set1_epi64x(value as i64)
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn from_words(words: [u64; N]) -> V {
        _mm256_loadu_si256(words.as_ptr() as *const __m256i)
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn to_words(v: V) -> [u64; N] {
        let mut words = [0u64; N];
        _mm256_storeu_si256(words.as_mut_ptr() as *mut __m256i, v);
        words
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn add(a: V, b: V) -> V {
        _mm256_add_epi64(a, b)
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn xor(a: V, b: V) -> V {
        _mm256_xor_si256(a, b)
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn rotr(a: V, bits: u32) -> V {
        _mm256_or_si256(_mm256_srl_epi64(a, _mm_cvtsi32_si128(bits as i32)), _mm256_sll_epi64(a, _mm_cvtsi32_si128(64 - bits as i32)))
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn shr(a: V, bits: u32) -> V {
        _mm256_srl_epi64(a, _mm_cvtsi32_si128(bits as i32))
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn ch(e: V, f: V, g: V) -> V {
        // g ^ (e & (f ^ g))
        _mm256_xor_si256(g, _mm256_and_si256(e, _mm256_xor_si256(f, g)))
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn maj(a: V, b: V, c: V) -> V {
        // (a & b) | (c & (a | b))
        _mm256_or_si256(_mm256_and_si256(a, b), _mm256_and_si256(c, _mm256_or_si256(a, b)))
    }
    sha512_lanes_impl!(#[target_feature(enable = "avx2")]);
}

/// Eight hashes at a time in 512-bit registers.
#[cfg(target_arch = "x86_64")]
mod avx512 {
    use std::arch::x86_64::*;
    pub(super) const N: usize = 8;
    type V = __m512i;
    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn splat(value: u64) -> V {
        _mm512_set1_epi64(value as i64)
    }
    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn from_words(words: [u64; N]) -> V {
        _mm512_loadu_si512(words.as_ptr() as *const _)
    }
    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn to_words(v: V) -> [u64; N] {
        let mut words = [0u64; N];
        _mm512_storeu_si512(words.as_mut_ptr() as *mut _, v);
        words
    }
    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn add(a: V, b: V) -> V {
        _mm512_add_epi64(a, b)
    }
    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn xor(a: V, b: V) -> V {
        _mm512_xor_si512(a, b)
    }
    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn rotr(a: V, bits: u32) -> V {
        _mm512_rorv_epi64(a, _mm512_set1_epi64(bits as i64))
    }
    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn shr(a: V, bits: u32) -> V {
        _mm512_srl_epi64(a, _mm_cvtsi32_si128(bits as i32))
    }
    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn ch(e: V, f: V, g: V) -> V {
        // Bitwise "if e then f else g".
        _mm512_ternarylogic_epi64::<0xCA>(e, f, g)
    }
    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn maj(a: V, b: V, c: V) -> V {
        // Bitwise majority.
        _mm512_ternarylogic_epi64::<0xE8>(a, b, c)
    }
    sha512_lanes_impl!(#[target_feature(enable = "avx512f")]);
}

/// SHA-512 of one message with the portable code.
fn sha512_one(message: &[u8]) -> [u8; 64] {
    // SAFETY: the portable functions use no CPU features; they are `unsafe` only because the
    // vector versions generated from the same source are.
    unsafe { portable::hash(&[message])[0] }
}

/// Whether a vector version gives the same digests as the portable code on this CPU. A vector
/// version that fails the check is not used.
fn agrees_with_portable<const N: usize>(hash: unsafe fn(&[&[u8]; N]) -> [[u8; 64]; N]) -> bool {
    // Lengths that end in one and in two padding blocks, with different bytes in every lane.
    [0usize, 5, 112, 300, 1000].iter().all(|&len| {
        let messages: [Vec<u8>; N] = std::array::from_fn(|lane| (0..len).map(|i| (i * 31 + lane * 97 + len) as u8).collect());
        let views: [&[u8]; N] = std::array::from_fn(|lane| &messages[lane][..]);
        // SAFETY: the caller passes a function only for features the CPU was found to support.
        let digests = unsafe { hash(&views) };
        (0..N).all(|lane| digests[lane] == sha512_one(&messages[lane]))
    })
}

/// How many hashes this CPU computes side by side: 8 with AVX-512, 4 with AVX2, otherwise 1.
pub fn lanes() -> usize {
    lazy_static! {
        static ref LANES: usize = detected_lanes();
    }
    *LANES
}

fn detected_lanes() -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx512f") {
            if agrees_with_portable(avx512::hash) {
                return 8;
            }
            eprintln!("multisign: the AVX-512 hash failed its self-check and is not used");
        }
        if is_x86_feature_detected!("avx2") {
            if agrees_with_portable(avx2::hash) {
                return 4;
            }
            eprintln!("multisign: the AVX2 hash failed its self-check and is not used");
        }
    }
    1
}

/// SHA-512 of each of `messages`, which must all have the same length. `out[i]` receives the
/// digest of `messages[i]`.
pub fn sha512_many(messages: &[&[u8]], out: &mut [[u8; 64]]) {
    assert_eq!(messages.len(), out.len());
    let width = lanes();
    let mut at = 0;
    #[cfg(target_arch = "x86_64")]
    {
        if width == 8 {
            while messages.len() - at >= 8 {
                let group: &[&[u8]; 8] = messages[at..at + 8].try_into().unwrap();
                // SAFETY: `lanes()` returns 8 only when the CPU supports AVX-512F.
                out[at..at + 8].copy_from_slice(&unsafe { avx512::hash(group) });
                at += 8;
            }
        }
        if width >= 4 {
            while messages.len() - at >= 4 {
                let group: &[&[u8]; 4] = messages[at..at + 4].try_into().unwrap();
                // SAFETY: `lanes()` returns 4 or more only when the CPU supports AVX2.
                out[at..at + 4].copy_from_slice(&unsafe { avx2::hash(group) });
                at += 4;
            }
        }
    }
    let _ = width;
    while at < messages.len() {
        out[at] = sha512_one(messages[at]);
        at += 1;
    }
}

/// Bytes in front of a message in a [`SignBuffer`]: room for the two 32-byte values that
/// Ed25519 hashes ahead of the message.
pub const SIGN_PREFIX: usize = 64;

lazy_static! {
    /// The server's signing key in the form signing uses: secret scalar, nonce prefix and public key.
    static ref SERVER_KEY: (Scalar, [u8; 32], [u8; 32]) = {
        let secret = SecretKey::from_bytes(&SERVER_SIGNING_SEED).expect("Invalid server signing seed");
        let public: PublicKey = (&secret).into();
        let expanded = ExpandedSecretKey::from(&secret).to_bytes();
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 32];
        key.copy_from_slice(&expanded[..32]);
        nonce.copy_from_slice(&expanded[32..]);
        (Scalar::from_bits(key), nonce, public.to_bytes())
    };
}

/// Signs several messages of the same length with the server's key.
///
/// Each buffer holds [`SIGN_PREFIX`] bytes of scratch space followed by a message; the scratch
/// space is overwritten. Returns one signature per buffer, identical to what
/// [`crate::crypto::sign`] returns for the message.
pub fn sign_many(buffers: &mut [&mut [u8]]) -> Vec<[u8; SIGNATURE_LENGTH]> {
    let (key, nonce, public) = &*SERVER_KEY;
    let count = buffers.len();
    let mut digests = vec![[0u8; 64]; count];

    // r = H(nonce || message)
    for buffer in buffers.iter_mut() {
        assert!(buffer.len() >= SIGN_PREFIX, "A sign buffer starts with {} bytes of scratch space", SIGN_PREFIX);
        buffer[32..SIGN_PREFIX].copy_from_slice(nonce);
    }
    {
        let messages: Vec<&[u8]> = buffers.iter().map(|buffer| &buffer[32..]).collect();
        sha512_many(&messages, &mut digests);
    }
    let rs: Vec<Scalar> = digests.iter().map(Scalar::from_bytes_mod_order_wide).collect();

    // R = r * B, then k = H(R || public key || message)
    for (buffer, r) in buffers.iter_mut().zip(&rs) {
        let big_r = (r * &ED25519_BASEPOINT_TABLE).compress();
        buffer[..32].copy_from_slice(big_r.as_bytes());
        buffer[32..SIGN_PREFIX].copy_from_slice(public);
    }
    {
        let messages: Vec<&[u8]> = buffers.iter().map(|buffer| &buffer[..]).collect();
        sha512_many(&messages, &mut digests);
    }

    // s = k * key + r; the signature is R || s
    buffers
        .iter()
        .zip(&rs)
        .zip(&digests)
        .map(|((buffer, r), digest)| {
            let k = Scalar::from_bytes_mod_order_wide(digest);
            let s = &(&k * key) + r;
            let mut signature = [0u8; SIGNATURE_LENGTH];
            signature[..32].copy_from_slice(&buffer[..32]);
            signature[32..].copy_from_slice(s.as_bytes());
            signature
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use sha2::{Digest, Sha512};

    fn random(len: usize, rng: &mut ChaCha20Rng) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    #[test]
    fn lane_hashes_match_the_reference_for_every_padding_case() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        for len in [0, 1, 55, 111, 112, 113, 127, 128, 129, 239, 240, 241, 255, 256, 1000, 14208, 14240, 14272] {
            let messages: Vec<Vec<u8>> = (0..8).map(|_| random(len, &mut rng)).collect();
            let expected: Vec<Vec<u8>> = messages.iter().map(|message| Sha512::digest(message).to_vec()).collect();

            assert_eq!(sha512_one(&messages[0]).to_vec(), expected[0], "1 lane, length {}", len);
            #[cfg(target_arch = "x86_64")]
            {
                if is_x86_feature_detected!("avx2") {
                    let four = unsafe { avx2::hash(&std::array::from_fn(|lane| &messages[lane][..])) };
                    for lane in 0..4 {
                        assert_eq!(four[lane].to_vec(), expected[lane], "4 lanes, length {}", len);
                    }
                }
                if is_x86_feature_detected!("avx512f") {
                    let eight = unsafe { avx512::hash(&std::array::from_fn(|lane| &messages[lane][..])) };
                    for lane in 0..8 {
                        assert_eq!(eight[lane].to_vec(), expected[lane], "8 lanes, length {}", len);
                    }
                }
            }
        }
    }

    #[test]
    fn self_check_accepts_the_vector_versions_this_cpu_has() {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") {
                assert!(agrees_with_portable(avx2::hash));
            }
            if is_x86_feature_detected!("avx512f") {
                assert!(agrees_with_portable(avx512::hash));
            }
        }
        // A hash that returns something else is rejected.
        unsafe fn wrong(messages: &[&[u8]; 2]) -> [[u8; 64]; 2] {
            [[messages[0].len() as u8; 64]; 2]
        }
        assert!(!agrees_with_portable(wrong));
    }

    #[test]
    fn hashing_many_matches_the_reference_for_any_count() {
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        for count in 0..=19 {
            let messages: Vec<Vec<u8>> = (0..count).map(|_| random(300, &mut rng)).collect();
            let slices: Vec<&[u8]> = messages.iter().map(|message| &message[..]).collect();
            let mut digests = vec![[0u8; 64]; count];
            sha512_many(&slices, &mut digests);
            for (message, digest) in messages.iter().zip(&digests) {
                assert_eq!(digest.to_vec(), Sha512::digest(message).to_vec(), "{} messages", count);
            }
        }
    }

    #[test]
    fn signatures_are_the_ones_the_single_signer_gives() {
        let mut rng = ChaCha20Rng::seed_from_u64(13);
        for (count, len) in [(1, 0), (3, 17), (8, 14208), (13, 14208), (21, 500)] {
            let messages: Vec<Vec<u8>> = (0..count).map(|_| random(len, &mut rng)).collect();
            let mut buffers: Vec<Vec<u8>> = messages.iter().map(|message| [&random(SIGN_PREFIX, &mut rng)[..], &message[..]].concat()).collect();
            let mut views: Vec<&mut [u8]> = buffers.iter_mut().map(|buffer| &mut buffer[..]).collect();
            let signatures = sign_many(&mut views);
            assert_eq!(signatures.len(), count);
            for (message, signature) in messages.iter().zip(&signatures) {
                assert_eq!(signature.to_vec(), crate::crypto::sign(message).unwrap());
                crate::crypto::verify(message, signature).unwrap();
            }
        }
    }
}
