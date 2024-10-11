use rand::{rngs::ThreadRng, thread_rng, Rng, RngCore};

use crate::{BUCKET_SIZE, D, LAMBDA};

pub(crate) type Timestamp = u64;

#[derive(Debug, Clone, PartialEq)]
pub struct Path(Vec<Direction>);
pub type Metadata = Vec<(Path, Key, Timestamp)>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Direction {
    Left,
    Right,
}

impl Into<u8> for Direction {
    fn into(self) -> u8 {
        match self {
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
            let bit: u8 = (*direction).into();

            bytes[byte_index] |= bit << bit_position;
        }

        bytes
    }
}

impl From<Vec<u8>> for Path {
    fn from(bytes: Vec<u8>) -> Self {
        let directions: Vec<Direction> = bytes
            .into_iter()
            .flat_map(|byte| {
                (0..8).map(move |bit_position| {
                    (byte >> bit_position) & 1 
                })
            })
            .take(D)
            .map(Direction::from)
            .collect();
        Path(directions)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Block(pub(crate) Vec<u8>);

impl Block {
    pub(crate) fn new(data: Vec<u8>) -> Self {
        Block(data)
    }

    pub(crate) fn new_random() -> Self {
        let mut rng = thread_rng();
        let mut block = vec![0u8; BUCKET_SIZE / 8];
        rng.fill_bytes(&mut block);

        Block(block)
    }
}

pub(crate) type Bucket = Vec<Block>;


#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Key(pub(crate) Vec<u8>);

impl Key {
    pub(crate) fn new(bytes: Vec<u8>) -> Key {
        Key(bytes)
    }

    pub(crate) fn random(rng: &mut ThreadRng) -> Key {
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
        assert_eq!(encoded, Vec::<u8>::new(), "Encoding an empty Path should result in an empty Vec<u8>");
    }

    #[test]
    fn test_into_vecu8_single_direction_left() {
        let path = Path(vec![Direction::Left]);
        let encoded: Vec<u8> = path.into();
        assert_eq!(encoded, vec![0b00000000], "Single Left direction should encode to 0");
    }

    #[test]
    fn test_into_vecu8_single_direction_right() {
        let path = Path(vec![Direction::Right]);
        let encoded: Vec<u8> = path.into();
        assert_eq!(encoded, vec![0b00000001], "Single Right direction should encode to 1");
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
        assert_eq!(encoded, vec![0b10110010, 0b00000000], "Multiple Directions should encode correctly with spillover");
    }

    #[test]
    fn test_from_vecu8_empty() {
        let bytes = Vec::<u8>::new();
        let path = Path::from(bytes);
        assert_eq!(path.0, Vec::<Direction>::new(), "Decoding an empty Vec<u8> should result in an empty Path");
    }

    #[test]
    fn test_from_vecu8_single_byte() {
        let bytes = vec![0b00000001];
        let path = Path::from(bytes);
        assert_eq!(path.0, vec![Direction::Right, Direction::Left, Direction::Left, Direction::Left, Direction::Left, Direction::Left, Direction::Left, Direction::Left], "Decoding Vec<u8> with single bit set should result in one Right direction");
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
            ],
            "Decoding multiple bytes should result in the correct sequence of Directions"
        );
    }

    #[test]
    fn test_round_trip_conversion() {
        let original_path = Path(vec![
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
        ]);
        
        let encoded: Vec<u8> = original_path.clone().into();
        let decoded_path = Path::from(encoded.clone());
        assert_eq!(original_path.0.len(), decoded_path.0.len(), "Round-trip conversion should preserve the length of the Path");
        assert_eq!(original_path.0, decoded_path.0, "Round-trip conversion should preserve the Directions in the Path");
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
        assert_eq!(encoded, vec![0b10101010], "Path with 8 Directions should encode to exactly one byte");
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
            ],
            "Decoding a single byte should result in the correct sequence of 8 Directions"
        );
    }

    #[test]
    fn test_more_than_d_bits() {
        let bytes = vec![0b10101010, 0b01010101, 0b11110000, 0b00001111, 0b11001100, 0b00110011, 0b11111111, 0b00000000, 0b10101010, 0b01010101, 0b11110000, 0b00001111, 0b11001100, 0b00110011, 0b11111111, 0b00000000, 0b10101010, 0b01010101, 0b11110000, 0b00001111, 0b11001100, 0b00110011, 0b11111111, 0b00000000, 0b10101010, 0b01010101, 0b11110000, 0b00001111, 0b11001100, 0b00110011, 0b11111111, 0b00000000, 0b10101010, 0b01010101, 0b11110000, 0b00001111, 0b11001100, 0b00110011, 0b11111111, 0b00000000, 0b10101010, 0b01010101, 0b11110000, 0b00001111, 0b11001100, 0b00110011, 0b11111111, 0b00000000, 0b10101010, 0b01010101];
        let path = Path::from(bytes.clone());

        assert_eq!(path.0.len(), D, "Path length should be exactly D");
        
        for (i, direction) in path.0.iter().enumerate() {
            let byte_index = i / 8;
            let bit_position = i % 8;
            let bit = (bytes[byte_index] >> bit_position) & 1;
            assert_eq!(*direction, Direction::from(bit), "Direction at index {} should match the corresponding bit in the byte array", i);
        }
    }
}