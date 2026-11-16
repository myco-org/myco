//! # Myco Data Types
//! 
//! This module contains the core data types used throughout the Myco library.
//! 
//! The main types defined here are:
//! - `Key`: Cryptographic keys used for encryption and PRF operations
//! - `Path`: Binary paths used in the tree data structure
//! - `Bucket`: Storage units containing encrypted message blocks
//! - `Metadata`: Associated metadata for message blocks including paths and timestamps
//! 
//! These types form the foundation for Myco's metadata-hiding encrypted messaging system,
//! enabling secure communication while obscuring patterns of interaction between users.
//! The types are designed to work together to implement the ORAM-inspired data structure
//! that provides efficient read/write operations while maintaining strong privacy guarantees.

use crate::{constants::{D, LAMBDA}, crypto};
use rand::{seq::SliceRandom, Rng, RngCore};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use crate::{tree::TreeValue, constants::{BLOCK_SIZE, Z}};

pub(crate) type Timestamp = u64;

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, Eq, Hash)]
pub struct TreeMycoKey;
impl Size for TreeMycoKey {
    const SIZE: usize = LAMBDA / 8;
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
/// Individual metadata entry for a message block
pub struct Metadata {
    /// Path in the tree
    pub path: Path,
    /// Cryptographic key
    pub key: Key<TreeMycoKey>,
    /// Timestamp of the message
    pub timestamp: Timestamp,
}

impl Metadata {
    /// Create a new Metadata instance
    pub fn new(path: Path, key: Key<TreeMycoKey>, timestamp: Timestamp) -> Self {
        Metadata {
            path,
            key,
            timestamp,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
/// A bucket containing multiple metadata entries
pub struct MetadataBucket(Vec<Metadata>);

impl MetadataBucket {
    /// Create a new MetadataBucket instance with a single entry
    pub fn new(metadata: Metadata) -> Self {
        MetadataBucket(vec![metadata])
    }

    /// Create a new MetadataBucket with capacity for specified number of entries
    pub fn with_capacity<R: RngCore + Rng>(capacity: usize, _: &mut R) -> Self {
        MetadataBucket(Vec::with_capacity(capacity))
    }

    /// Get the number of entries in the MetadataBucket
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Add a new entry to the MetadataBucket
    pub fn push(&mut self, metadata: Metadata) {
        self.0.push(metadata);
    }

    /// Retrieve a reference to a Metadata entry by index.
    pub fn get(&self, index: usize) -> Option<&Metadata> {
        self.0.get(index)
    }

    /// Shuffle the entries in the MetadataBucket using a random number generator
    pub fn shuffle<R: RngCore + Rng>(&mut self, rng: &mut R) {
        self.0.shuffle(rng);
    }
}

impl TreeValue for MetadataBucket {
    fn new_random(rng: &mut ChaCha20Rng) -> Self {
        let metadata = Metadata::new(
            Path::random(rng),
            Key::random(rng),
            rng.gen(),
        );
        MetadataBucket::new(metadata)
    }
}

impl TreeValue for Bucket {
    /// Create a new random Bucket instance with a given size
    fn new_random(rng: &mut ChaCha20Rng) -> Self {
        Bucket::new_random(BLOCK_SIZE, Z, rng)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// An enum representing the direction of a path in the tree
pub enum Direction {
    /// Left direction
    Left,
    /// Right direction
    Right,
}

impl From<Direction> for u8 {
    fn from(val: Direction) -> Self {
        match val {
            Direction::Left => 0,
            Direction::Right => 1,
        }
    }
}

impl From<u8> for Direction {
    fn from(value: u8) -> Self {
        match value {
            0 => Direction::Left,
            1 => Direction::Right,
            _ => panic!("Invalid direction value"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// A binary path in the tree, represented as a vector of directions
pub struct Path(pub Vec<Direction>);

impl Path {
    /// Create a new Path instance with a given vector of directions
    pub fn new(directions: Vec<Direction>) -> Self {
        Path(directions)
    }

    /// Get the length of the path
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Add a direction to the path
    pub fn push(&mut self, direction: Direction) {
        self.0.push(direction);
    }

    /// Create a new random Path instance with a given length
    pub fn random<R: RngCore + Rng>(rng: &mut R) -> Self {
        Path((0..D).map(|_| rng.gen_range(0..2).into()).collect())
    }

    /// Check if the path is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Iterator for Path {
    type Item = Direction;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            None
        } else {
            Some(self.0.remove(0))
        }
    }
}

impl<'a> IntoIterator for &'a Path {
    type Item = &'a Direction;
    type IntoIter = std::slice::Iter<'a, Direction>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl From<Path> for Vec<u8> {
    fn from(path: Path) -> Self {
        let num_bytes = (path.0.len() + 7) / 8;
        let mut bytes = vec![0u8; num_bytes];

        for (i, direction) in path.0.iter().enumerate() {
            let byte_index = i / 8;
            let bit_position = i % 8;
            let bit: u8 = u8::from(*direction);

            bytes[byte_index] |= bit << bit_position;
        }

        bytes
    }
}

impl From<Vec<u8>> for Path {
    fn from(bytes: Vec<u8>) -> Self {
        let directions: Vec<Direction> = bytes
            .into_iter()
            .flat_map(|byte| (0..8).map(move |bit_position| (byte >> bit_position) & 1))
            .take(D)
            .map(Direction::from)
            .collect();
        Path(directions)
    }
}

impl From<usize> for Path {
    fn from(value: usize) -> Self {
        let mut directions = Vec::new();
        let mut value = value;
        if value > 1 {
            value = value >> 1;
            while value > 0 {
                directions.push(Direction::from((value & 1) as u8));
                value >>= 1;
            }
        }
        Path(directions)
    }
}

impl Default for Path {
    fn default() -> Self {
        Path(Vec::new())
    }
}

use std::marker::PhantomData;

use crate::utils::generate_dummy_message;


#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, Default)]
/// A block of data, represented as a vector of bytes
pub struct Block(pub Vec<u8>);

impl Block {
    /// Create a new Block instance with a given vector of bytes
    pub fn new(data: Vec<u8>) -> Self {
        Block(data)
    }

    /// Create a new random Block instance with a given size
    pub fn new_random(size: usize, rng: &mut ChaCha20Rng) -> Self {
        let mut block = vec![0u8; size];
        rng.fill_bytes(&mut block);

        Block(block)
    }

    /// Creates a new dummy Block of specified size using utils::generate_dummy_message
    ///
    /// # Arguments
    /// * `size` - The size of the dummy block to create
    ///
    /// # Returns
    /// A new Block containing dummy encrypted data
    pub fn new_dummy(size: usize, rng: &mut ChaCha20Rng) -> Self {
        let ciphertext = generate_dummy_message(size, rng).unwrap();

        Block(ciphertext)
    }

    /// Check if the block is equal to the default value (empty)
    pub fn is_default(&self) -> bool {
        self.0.is_empty()
    }

    /// Create a new Block with preallocated capacity
    /// 
    /// # Arguments
    /// * `size` - The size of the block in bytes
    /// * `rng` - Random number generator
    /// 
    /// # Returns
    /// A new Block with capacity for the specified number of bytes
    pub fn with_capacity(size: usize, rng: &mut ChaCha20Rng) -> Self {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);
        Block(data)
    }
}

use std::ops::{Deref, DerefMut};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bucket(pub Vec<Block>, pub Option<Vec<u8>>);

impl Default for Bucket {
    fn default() -> Self {
        Bucket(Vec::new(), None)
    }
}

impl Bucket {
    /// Creates a bucket that keeps all of its bytes in one contiguous block.
    ///
    /// Server2 never looks inside a bucket, and converting a bucket to its wire form
    /// concatenates its blocks, so this is byte-for-byte the same bucket as one that is
    /// split into per-block allocations, without the per-block heap overhead.
    pub fn contiguous(data: Vec<u8>, signature: Option<Vec<u8>>) -> Self {
        if data.is_empty() {
            return Bucket(Vec::new(), signature);
        }
        Bucket(vec![Block::new(data)], signature)
    }

    pub fn new_empty() -> Self {
        Self::default()
    }
}

impl Deref for Bucket {
    type Target = Vec<Block>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Bucket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Bucket {
    /// Create a new bucket with given blocks
    pub fn new(blocks: Vec<Block>) -> Self {
        Bucket(blocks, None)
    }

    /// Check if the bucket is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get the number of blocks in the bucket
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Add a block to the bucket
    pub fn push(&mut self, block: Block) {
        self.0.push(block);
    }

    /// Get the block at a specific index
    pub fn get(&self, index: usize) -> Option<&Block> {
        self.0.get(index)
    }

    /// Shuffle the blocks in the bucket using a random number generator
    pub fn shuffle<R: RngCore + Rng>(&mut self, rng: &mut R) {
        self.0.shuffle(rng);
    }

    /// Get an iterator over the blocks in the bucket
    pub fn iter(&self) -> std::slice::Iter<'_, Block> {
        self.0.iter()
    }

    /// Get an iterator over the blocks in the bucket
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, Block> {
        self.0.iter_mut()
    }

    /// Clear the bucket
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Create a new random Bucket instance with a given size
    pub fn new_random(block_size: usize, bucket_size: usize, rng: &mut ChaCha20Rng) -> Self {
        Bucket((0..bucket_size).map(|_| Block::new_random(block_size, rng)).collect(), None)
    }

    /// Creates a new dummy Bucket of specified size using utils::generate_dummy_message
    pub fn new_dummy(block_size: usize, bucket_size: usize, rng: &mut ChaCha20Rng) -> Self {
        Bucket((0..bucket_size).map(|_| Block::new_dummy(block_size, rng)).collect(), None)
    }

    /// Reset a bucket by clearing block contents while preserving allocated memory
    pub fn reset(&mut self) {
        self.0.clear();
    }
    
    /// Reset a bucket and shrink memory allocation
    pub fn reset_and_shrink(&mut self) {
        // Clear the blocks and release memory
        self.0.clear();
        self.0.shrink_to_fit();
        
        // Reset the signature to the default empty bucket signature
        self.1 = Some(crypto::sign(&[]).expect("Failed to sign empty bucket"));
    }

    /// Create a new bucket with preallocated and initialized blocks
    ///
    /// # Arguments
    /// * `block_size` - The size of each block in bytes
    /// * `bucket_capacity` - The number of blocks to preallocate
    /// * `rng` - Random number generator
    ///
    /// # Returns
    /// A new Bucket with the specified number of preallocated blocks
    pub fn with_capacity(block_size: usize, bucket_capacity: usize, rng: &mut ChaCha20Rng) -> Self {
        let blocks: Vec<Block> = (0..bucket_capacity)
            .map(|_| Block::with_capacity(block_size, rng))
            .collect();
        Bucket(blocks, None)
    }
    
    /// Ensure the bucket has capacity for at least `additional` more blocks
    pub fn reserve(&mut self, additional: usize) {
        self.0.reserve(additional);
    }
    
    /// Returns the number of blocks the bucket can hold without reallocating
    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

/// Trait defining the behavior and size for cryptographic keys
pub trait Size {
    const SIZE: usize;
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, Default)]
/// A cryptographic key, represented as a vector of bytes
pub struct Key<S: Size> {
    pub bytes: Vec<u8>,
    _marker: PhantomData<S>,
}

impl<S: Size> Key<S> {
    /// Create a new Key instance with a given vector of bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Key {
            bytes,
            _marker: PhantomData,
        }
    }

    /// Create a new random Key instance
    pub fn random<R: RngCore + Rng>(rng: &mut R) -> Self {
        Key {
            bytes: (0..S::SIZE).map(|_| rng.gen()).collect(),
            _marker: PhantomData,
        }
    }
}
