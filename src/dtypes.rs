use std::{
    fmt::{self, Display},
    ops::{Index, IndexMut},
};

use rand::{seq::SliceRandom, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use crate::{tree::TreeValue, BLOCK_SIZE, D, LAMBDA};

pub(crate) type Timestamp = u64;

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Metadata(Vec<(Path, Key, Timestamp)>);

impl Metadata {
    pub(crate) fn new(path: Path, key: Key, timestamp: Timestamp) -> Self {
        Metadata(vec![(path, key, timestamp)])
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn push(&mut self, path: Path, key: Key, timestamp: Timestamp) {
        self.0.push((path, key, timestamp));
    }

    pub(crate) fn get(&self, index: usize) -> Option<&(Path, Key, Timestamp)> {
        self.0.get(index)
    }

    pub(crate) fn shuffle<R: RngCore + Rng>(&mut self, rng: &mut R) {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
pub struct Path(Vec<Direction>);

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

impl Into<Vec<u8>> for Path {
    fn into(self) -> Vec<u8> {
        let num_bytes = (self.0.len() + 7) / 8;
        let mut bytes = vec![0u8; num_bytes];

        for (i, direction) in self.0.iter().enumerate() {
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
pub struct Block(pub(crate) Vec<u8>);

impl Block {
    pub(crate) fn new(data: Vec<u8>) -> Self {
        Block(data)
    }

    pub(crate) fn new_random() -> Self {
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
        Bucket(vec![Block::new_random(); BLOCK_SIZE])
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
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn push(&mut self, block: Block) {
        self.0.push(block);
    }

    pub(crate) fn get(&self, index: usize) -> Option<&Block> {
        self.0.get(index)
    }

    pub(crate) fn shuffle<R: RngCore + Rng>(&mut self, rng: &mut R) {
        self.0.shuffle(rng);
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Key(pub(crate) Vec<u8>);

impl Key {
    pub fn new(bytes: Vec<u8>) -> Key {
        Key(bytes)
    }

    pub fn random<R: RngCore + Rng>(rng: &mut R) -> Key {
        Key((0..LAMBDA / 8).map(|_| rng.gen()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_into_vecu8_empty_path() {
        let path = Path(Vec::new());
        let encoded: Vec<u8> = path.into();
        assert_eq!(
            encoded,
            Vec::<u8>::new(),
            "Encoding an empty Path should result in an empty Vec<u8>"
        );
    }

    #[test]
    fn test_into_vecu8_single_direction_left() {
        let path = Path(vec![Direction::Left]);
        let encoded: Vec<u8> = path.into();
        assert_eq!(
            encoded,
            vec![0b00000000],
            "Single Left direction should encode to 0"
        );
    }

    #[test]
    fn test_into_vecu8_single_direction_right() {
        let path = Path(vec![Direction::Right]);
        let encoded: Vec<u8> = path.into();
        assert_eq!(
            encoded,
            vec![0b00000001],
            "Single Right direction should encode to 1"
        );
    }

    #[test]
    fn test_into_vecu8_multiple_directions() {
        let path = Path(vec![
            Direction::Left,  // bit 0
            Direction::Right, // bit 1
            Direction::Left,  // bit 2
            Direction::Left,  // bit 3
            Direction::Right, // bit 4
            Direction::Right, // bit 5
            Direction::Left,  // bit 6
            Direction::Right, // bit 7
            Direction::Left,  // bit 8 (spill into second byte)
        ]);
        let encoded: Vec<u8> = path.into();
        assert_eq!(
            encoded,
            vec![0b10110010, 0b00000000],
            "Multiple Directions should encode correctly with spillover"
        );
    }

    #[test]
    fn test_from_vecu8_empty() {
        let bytes = Vec::<u8>::new();
        let path = Path::from(bytes);
        assert_eq!(
            path.0,
            Vec::<Direction>::new(),
            "Decoding an empty Vec<u8> should result in an empty Path"
        );
    }

    #[test]
    fn test_from_vecu8_single_byte() {
        let bytes = vec![0b00000001];
        let path = Path::from(bytes);
        assert_eq!(
            path.0,
            vec![
                Direction::Right,
                Direction::Left,
                Direction::Left,
                Direction::Left,
                Direction::Left,
                Direction::Left,
                Direction::Left,
                Direction::Left
            ]
            .into_iter()
            .take(D)
            .collect::<Vec<Direction>>(),
            "Decoding Vec<u8> with single bit set should result in one Right direction"
        );
    }

    #[test]
    fn test_from_vecu8_multiple_bytes() {
        let bytes = vec![0b10110010, 0b00000000];
        let path = Path::from(bytes);
        assert_eq!(
            path.0,
            vec![
                Direction::Left,  // bit 0
                Direction::Right, // bit 1
                Direction::Left,  // bit 2
                Direction::Left,  // bit 3
                Direction::Right, // bit 4
                Direction::Right, // bit 5
                Direction::Left,  // bit 6
                Direction::Right, // bit 7
                Direction::Left,  // bit 8
                Direction::Left,  // bit 9
                Direction::Left,  // bit 10
                Direction::Left,  // bit 11
                Direction::Left,  // bit 12
                Direction::Left,  // bit 13
                Direction::Left,  // bit 14
                Direction::Left,  // bit 15
            ]
            .into_iter()
            .take(D)
            .collect::<Vec<Direction>>(),
            "Decoding multiple bytes should result in the correct sequence of Directions"
        );
    }

    #[test]
    fn test_round_trip_conversion() {
        let original_path = Path(
            vec![
                Direction::Left,
                Direction::Right,
                Direction::Left,
                Direction::Right,
                Direction::Left,
                Direction::Left,
                Direction::Right,
                Direction::Right,
                Direction::Left,
                Direction::Right,
                Direction::Left,
                Direction::Left,
                Direction::Right,
                Direction::Right,
                Direction::Left,
                Direction::Right,
            ]
            .into_iter()
            .take(D)
            .collect(),
        );

        let encoded: Vec<u8> = original_path.clone().into();
        let decoded_path = Path::from(encoded.clone());
        assert_eq!(
            original_path.0.len(),
            decoded_path.0.len(),
            "Round-trip conversion should preserve the length of the Path"
        );
        assert_eq!(
            original_path.0, decoded_path.0,
            "Round-trip conversion should preserve the Directions in the Path"
        );
    }

    #[test]
    fn test_into_vecu8_exact_byte_length() {
        // Path length is exactly 8, should result in one byte
        let path = Path(vec![
            Direction::Left,  // 0
            Direction::Right, // 1
            Direction::Left,  // 2
            Direction::Right, // 3
            Direction::Left,  // 4
            Direction::Right, // 5
            Direction::Left,  // 6
            Direction::Right, // 7
        ]);
        let encoded: Vec<u8> = path.into();
        assert_eq!(
            encoded,
            vec![0b10101010],
            "Path with 8 Directions should encode to exactly one byte"
        );
    }

    #[test]
    fn test_from_vecu8_exact_byte_length() {
        let bytes = vec![0b10101010];
        let path = Path::from(bytes);
        assert_eq!(
            path.0,
            vec![
                Direction::Left,  // 0
                Direction::Right, // 1
                Direction::Left,  // 2
                Direction::Right, // 3
                Direction::Left,  // 4
                Direction::Right, // 5
                Direction::Left,  // 6
                Direction::Right, // 7
            ]
            .into_iter()
            .take(D)
            .collect::<Vec<Direction>>(),
            "Decoding a single byte should result in the correct sequence of 8 Directions"
        );
    }

    #[test]
    fn test_more_than_d_bits() {
        let bytes = vec![
            0b10101010, 0b01010101, 0b11110000, 0b00001111, 0b11001100, 0b00110011, 0b11111111,
            0b00000000, 0b10101010, 0b01010101, 0b11110000, 0b00001111, 0b11001100, 0b00110011,
            0b11111111, 0b00000000, 0b10101010, 0b01010101, 0b11110000, 0b00001111, 0b11001100,
            0b00110011, 0b11111111, 0b00000000, 0b10101010, 0b01010101, 0b11110000, 0b00001111,
            0b11001100, 0b00110011, 0b11111111, 0b00000000, 0b10101010, 0b01010101, 0b11110000,
            0b00001111, 0b11001100, 0b00110011, 0b11111111, 0b00000000, 0b10101010, 0b01010101,
            0b11110000, 0b00001111, 0b11001100, 0b00110011, 0b11111111, 0b00000000, 0b10101010,
            0b01010101,
        ];
        let path = Path::from(bytes.clone());

        assert_eq!(path.0.len(), D, "Path length should be exactly D");

        for (i, direction) in path.0.iter().enumerate() {
            let byte_index = i / 8;
            let bit_position = i % 8;
            let bit = (bytes[byte_index] >> bit_position) & 1;
            assert_eq!(
                *direction,
                Direction::from(bit),
                "Direction at index {} should match the corresponding bit in the byte array",
                i
            );
        }
    }
}
