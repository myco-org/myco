use std::{
    fmt::{self, Display},
    ops::{Index, IndexMut},
};

use rand::{seq::SliceRandom, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use crate::{tree::TreeValue, BLOCK_SIZE, D, LAMBDA, Z};

pub(crate) type Timestamp = u64;

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Metadata(Vec<(Path, Key, Timestamp)>);

impl Metadata {
    pub fn new(path: Path, key: Key, timestamp: Timestamp) -> Self {
        Metadata(vec![(path, key, timestamp)])
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn push(&mut self, path: Path, key: Key, timestamp: Timestamp) {
        self.0.push((path, key, timestamp));
    }

    pub fn get(&self, index: usize) -> Option<&(Path, Key, Timestamp)> {
        self.0.get(index)
    }

    pub fn shuffle<R: RngCore + Rng>(&mut self, rng: &mut R) {
        self.0.shuffle(rng);
    }
}

impl TreeValue for Metadata {
    fn new_random() -> Self {
        let mut rng = ChaCha20Rng::from_entropy();
        let timestamp = rng.gen();
        Metadata(vec![(
            Path::random(&mut rng),
            Key::random(&mut rng),
            timestamp,
        )])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Direction {
    Left,
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
pub struct Path(pub Vec<Direction>);

impl Path {
    pub fn new(directions: Vec<Direction>) -> Self {
        Path(directions)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn push(&mut self, direction: Direction) {
        self.0.push(direction);
    }

    pub fn random<R: RngCore + Rng>(rng: &mut R) -> Self {
        Path((0..D).map(|_| rng.gen_range(0..2).into()).collect())
    }

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

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Block(pub Vec<u8>);

impl Block {
    pub fn new(data: Vec<u8>) -> Self {
        Block(data)
    }

    pub fn new_random() -> Self {
        let mut rng = ChaCha20Rng::from_entropy(); // Use ChaCha20Rng
        let mut block = vec![0u8; BLOCK_SIZE];
        rng.fill_bytes(&mut block);
        Block(block)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Default, Serialize, Deserialize)]
pub struct Bucket(Vec<Block>);

impl TreeValue for Bucket {
    fn new_random() -> Self {
        Bucket(vec![Block::new_random(); Z])
    }
}

impl Iterator for Bucket {
    type Item = Block;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.pop()
    }
}

impl Index<usize> for Bucket {
    type Output = Block;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for Bucket {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl Bucket {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn push(&mut self, block: Block) {
        self.0.push(block);
    }

    pub fn get(&self, index: usize) -> Option<&Block> {
        self.0.get(index)
    }

    pub fn shuffle<R: RngCore + Rng>(&mut self, rng: &mut R) {
        self.0.shuffle(rng);
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Block> {
        self.0.iter()
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Key(pub Vec<u8>);

impl Key {
    pub fn new(bytes: Vec<u8>) -> Key {
        Key(bytes)
    }

    pub fn random<R: RngCore + Rng>(rng: &mut R) -> Key {
        Key((0..LAMBDA / 8).map(|_| rng.gen()).collect())
    }
}

