use std::{
    cmp::max,
    fmt::{self, Debug, Write},
};

use crate::{Direction, Path};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BinaryTree<T> {
    pub(crate) value: Vec<Option<T>>,
}

pub(crate) trait TreeValue: Clone + Debug + PartialEq + Default {
    fn new_random() -> Self;
}

impl<T: TreeValue> BinaryTree<T> {
    pub(crate) fn new(value: T) -> Self {
        BinaryTree {
            value: vec![None, Some(value)],
        }
    }

    pub fn new_empty() -> Self {
        BinaryTree {
            value: vec![None; 2],
        }
    }

    pub fn new_with_depth(depth: usize) -> Self {
        BinaryTree {
            value: vec![None; (1 << depth) + 1],
        }
    }

    pub fn fill(&mut self, value: T) {
        self.value[1..].fill(Some(value));
    }

    pub fn fill_with_random(&mut self) {
        self.value = vec![Some(T::new_random()); 1 << self.height()];
    }

    pub fn insert_path(&mut self, path: Path, values: Vec<T>) {
        let mut idx: usize = 1;
        self.value[1] = Some(values[0].clone());

        for (direction, value) in path.zip(&values[1..]) {
            idx = 2 * idx + u8::from(direction) as usize;
            if idx + 1 >= self.value.len() {
                self.value.resize((idx + 1).next_power_of_two(), None);
            }
            self.value[idx] = Some(value.clone());
        }
    }

    pub fn from_vec_with_paths(items: Vec<(Vec<T>, Path)>) -> Self
    where
        T: TreeValue,
    {
        let mut tree = BinaryTree::new_empty();
        for (values, path) in items {
            tree.insert_path(path, values);
        }
        tree
    }

    pub fn height(&self) -> usize {
        ((self.value.len() - 1) as f64).log2().ceil() as usize
    }

    pub fn get(&self, path: &Path) -> Option<T> {
        let mut current = self.value[1].clone();
        let mut idx = 1;
        for &direction in path {
            idx = 2 * idx + u8::from(direction) as usize;
            if idx >= self.value.len() {
                return None;
            }
            current = self.value[idx].clone();
        }

        current
    }

    pub fn get_mut(&mut self, path: &Path) -> Option<&mut T> {
        let mut idx = 1;
        for &direction in path {
            idx = 2 * idx + u8::from(direction) as usize;
            if idx >= self.value.len() {
                return None;
            }
        }
        self.value[idx].as_mut()
    }

    pub fn get_all_nodes_along_path(&self, path: &Path) -> Vec<T> {
        let mut nodes = vec![];
        let mut idx = 1;

        // Include the root node if it has a value
        if let Some(value) = &self.value[1] {
            nodes.push(value.clone());
        }

        for &direction in path {
            idx = 2 * idx + u8::from(direction) as usize;

            if idx >= self.value.len() || self.value[idx].is_none() {
                return nodes;
            }
            nodes.push(self.value[idx].clone().unwrap());
        }

        nodes
    }

    pub fn get_index(&self, idx: usize) -> Option<&T> {
        self.value.get(idx).and_then(|v| v.as_ref())
    }

    pub fn get_index_mut(&mut self, idx: usize) -> Option<&mut T> {
        self.value.get_mut(idx).and_then(|v| v.as_mut())
    }

    // Returns the index of the LCA and the path to it.
    pub fn lca(&self, path: &Path) -> Option<(usize, Path)> {
        let mut current_path = Path::new(Vec::new());
        let mut idx = 1;

        for &direction in path {
            let next_idx = 2 * idx + u8::from(direction) as usize;
            if next_idx >= self.value.len() || self.value[next_idx].is_none() {
                return Some((idx, current_path));
            }
            idx = next_idx;
            current_path.push(direction);
        }

        Some((idx, current_path))
    }

    pub fn write(&mut self, value: T, path: Path) {
        let mut idx = 1;
        for direction in path {
            idx = 2 * idx + u8::from(direction) as usize;
            if idx >= self.value.len() {
                self.value.resize((idx + 1).next_power_of_two(), None);
            }
        }

        self.value[idx] = Some(value);
    }

    pub fn overwrite(&mut self, other: &BinaryTree<T>) {
        if self.value.len() < other.value.len() {
            self.value.resize(other.value.len(), None);
        }
        self.value
            .iter_mut()
            .zip(other.value.iter())
            .for_each(|(a, b)| {
                if b.is_some() {
                    *a = b.clone();
                }
            });
    }

    pub fn zip<S: Clone>(&self, rhs: &BinaryTree<S>) -> Vec<(Option<T>, Option<S>, Path)> {
        let len = max(self.value.len(), rhs.value.len());
        let mut lhs = self.value.clone();
        let mut rhs = rhs.value.clone();

        lhs.resize(len, None);
        rhs.resize(len, None);

        lhs.iter()
            .zip(rhs.iter())
            .enumerate()
            .filter_map(|(i, (a, b))| {
                if a.is_some() {
                    Some((a.clone(), b.clone(), Path::from(i)))
                } else {
                    None
                }
            })
            .collect()
    }
}

impl<T: fmt::Debug + TreeValue> fmt::Display for BinaryTree<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut output = String::new();
        let height = self.height() as u32;
        let mut level_start = 0;
        let mut level_end = 1;

        for level in 0..height {
            let spacing = 2usize.pow(height - level as u32) - 1;
            let between = 2usize.pow(height - level as u32 + 1) - 1;

            // Print leading spaces
            for _ in 0..spacing {
                output.push(' ');
            }

            // Print nodes and connections
            for i in level_start..level_end {
                if i < self.value.len() {
                    match &self.value[i] {
                        Some(val) => write!(output, "{:?}", val)?,
                        None => write!(output, " ")?,
                    }
                } else {
                    write!(output, " ")?;
                }

                // Print spaces and connections between nodes
                if i < level_end - 1 {
                    let mut connection = String::new();
                    for _ in 0..between {
                        connection.push('─');
                    }
                    write!(output, "{}", connection)?;
                }
            }

            output.push('\n');

            // Print connections to next level
            if level < height - 1 {
                for _ in 0..spacing - 1 {
                    output.push(' ');
                }
                for i in level_start..level_end {
                    if i < self.value.len() && self.value[i].is_some() {
                        output.push('/');
                        for _ in 0..between / 2 {
                            output.push(' ');
                        }
                        output.push('\\');
                        for _ in 0..between / 2 {
                            output.push(' ');
                        }
                    } else {
                        for _ in 0..between + 2 {
                            output.push(' ');
                        }
                    }
                }
                output.push('\n');
            }

            level_start = level_end;
            level_end = level_end * 2 + 1;
        }

        write!(f, "{}", output)
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng, seq::index};
    use rand_chacha::ChaCha20Rng;

    use super::*;

    #[derive(Default, Debug, Clone, PartialEq)]
    struct IntWrapper(i32);

    impl TreeValue for IntWrapper {
        fn new_random() -> Self {
            let mut rng = ChaCha20Rng::from_entropy();
            IntWrapper(rng.gen())
        }
    }

    #[test]
    fn test_int_wrapper() {
        // Test that IntWrapper implements TreeValue
        let random_value = IntWrapper::new_random();
        assert!(random_value.0 >= i32::MIN && random_value.0 <= i32::MAX);

        // Test creating a tree with IntWrapper
        let tree = BinaryTree::new(IntWrapper(42));
        assert_eq!(tree.value[1], Some(IntWrapper(42)));

        // Test creating a tree with depth
        let tree_with_depth = BinaryTree::<IntWrapper>::new_with_depth(2);
        assert_eq!(tree_with_depth.height(), 2);
    }

    #[test]
    fn test_get() {
        // Create a tree with some values, including non-leaf nodes
        let items = vec![
            (
                vec![
                    IntWrapper(0),
                    IntWrapper(1),
                    IntWrapper(2),
                    IntWrapper(3),
                    IntWrapper(1),
                ],
                Path::new(vec![
                    Direction::Left,
                    Direction::Left,
                    Direction::Left,
                    Direction::Left,
                ]),
            ),
            (
                vec![
                    IntWrapper(0),
                    IntWrapper(1),
                    IntWrapper(2),
                    IntWrapper(3),
                    IntWrapper(2),
                ],
                Path::new(vec![
                    Direction::Left,
                    Direction::Left,
                    Direction::Right,
                    Direction::Right,
                ]),
            ),
            (
                vec![
                    IntWrapper(0),
                    IntWrapper(1),
                    IntWrapper(2),
                    IntWrapper(3),
                    IntWrapper(3),
                ],
                Path::new(vec![
                    Direction::Left,
                    Direction::Right,
                    Direction::Left,
                    Direction::Left,
                ]),
            ),
            (
                vec![
                    IntWrapper(0),
                    IntWrapper(1),
                    IntWrapper(2),
                    IntWrapper(3),
                    IntWrapper(4),
                ],
                Path::new(vec![
                    Direction::Right,
                    Direction::Left,
                    Direction::Left,
                    Direction::Left,
                ]),
            ),
            (
                vec![
                    IntWrapper(0),
                    IntWrapper(1),
                    IntWrapper(2),
                    IntWrapper(3),
                    IntWrapper(5),
                ],
                Path::new(vec![
                    Direction::Right,
                    Direction::Left,
                    Direction::Right,
                    Direction::Right,
                ]),
            ),
            (
                vec![
                    IntWrapper(0),
                    IntWrapper(1),
                    IntWrapper(2),
                    IntWrapper(3),
                    IntWrapper(6),
                ],
                Path::new(vec![
                    Direction::Right,
                    Direction::Right,
                    Direction::Left,
                    Direction::Left,
                ]),
            ),
            (
                vec![
                    IntWrapper(0),
                    IntWrapper(1),
                    IntWrapper(2),
                    IntWrapper(3),
                    IntWrapper(7),
                ],
                Path::new(vec![
                    Direction::Right,
                    Direction::Right,
                    Direction::Right,
                    Direction::Left,
                ]),
            ),
            (
                vec![
                    IntWrapper(0),
                    IntWrapper(1),
                    IntWrapper(2),
                    IntWrapper(3),
                    IntWrapper(8),
                ],
                Path::new(vec![
                    Direction::Right,
                    Direction::Right,
                    Direction::Right,
                    Direction::Right,
                ]),
            ),
        ];
        let tree = BinaryTree::from_vec_with_paths(items);

        // Test get method for existing paths
        assert_eq!(
            tree.get(&Path::new(vec![
                Direction::Left,
                Direction::Left,
                Direction::Left,
                Direction::Left,
            ])),
            Some(IntWrapper(1))
        );
        assert_eq!(
            tree.get(&Path::new(vec![
                Direction::Left,
                Direction::Left,
                Direction::Right,
                Direction::Right
            ])),
            Some(IntWrapper(2))
        );
        assert_eq!(
            tree.get(&Path::new(vec![
                Direction::Right,
                Direction::Right,
                Direction::Right,
                Direction::Right
            ])),
            Some(IntWrapper(8))
        );

        // Test get method for non-leaf nodes
        assert_eq!(
            tree.get(&Path::new(vec![Direction::Left])),
            Some(IntWrapper(1))
        );
        assert_eq!(
            tree.get(&Path::new(vec![Direction::Right, Direction::Left])),
            Some(IntWrapper(2))
        );

        // Test get method for root
        assert_eq!(tree.get(&Path::new(vec![])), Some(IntWrapper(0)));

        // Test get method for non-existing paths
        assert_eq!(
            tree.get(&Path::new(vec![
                Direction::Left,
                Direction::Left,
                Direction::Left,
                Direction::Right
            ])),
            None
        );
        assert_eq!(
            tree.get(&Path::new(vec![
                Direction::Right,
                Direction::Right,
                Direction::Left,
                Direction::Right
            ])),
            None
        );
        assert_eq!(
            tree.get(&Path::new(vec![
                Direction::Left,
                Direction::Right,
                Direction::Right,
                Direction::Right
            ])),
            None
        );
    }

    #[test]
    fn test_lca() {
        // Create a binary tree:
        //         7
        //        / \
        //       5   6
        //      / \ / \
        //     1  2 3 4
        let items = vec![
            (vec![IntWrapper(7)], Path::new(vec![])), // Root node
            (
                vec![IntWrapper(7), IntWrapper(5)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(7), IntWrapper(6)],
                Path::new(vec![Direction::Right]),
            ),
            (
                vec![IntWrapper(7), IntWrapper(5), IntWrapper(1)],
                Path::new(vec![Direction::Left, Direction::Left]),
            ),
            (
                vec![IntWrapper(7), IntWrapper(5), IntWrapper(2)],
                Path::new(vec![Direction::Left, Direction::Right]),
            ),
            (
                vec![IntWrapper(7), IntWrapper(6), IntWrapper(3)],
                Path::new(vec![Direction::Right, Direction::Left]),
            ),
            (
                vec![IntWrapper(7), IntWrapper(6), IntWrapper(4)],
                Path::new(vec![Direction::Right, Direction::Right]),
            ),
        ];
        let tree = BinaryTree::from_vec_with_paths(items);

        // Test lca with various paths
        let path1 = Path::new(vec![Direction::Left, Direction::Left]);
        assert_eq!(tree.lca(&path1), Some((4, path1.clone())));

        let path2 = Path::new(vec![Direction::Right, Direction::Right]);
        assert_eq!(tree.lca(&path2), Some((7, path2.clone())));

        let path3 = Path::new(vec![]);
        assert_eq!(tree.lca(&path3), Some((1, path3.clone())));

        let path4 = Path::new(vec![Direction::Left]);
        assert_eq!(tree.lca(&path4), Some((2, path4.clone())));

        let path5 = Path::new(vec![Direction::Left, Direction::Right, Direction::Left]);
        assert_eq!(
            tree.lca(&path5),
            Some((
                5,
                Path::new(vec![Direction::Left, Direction::Right])
            ))
        );

        let path6 = Path::new(vec![Direction::Right, Direction::Left, Direction::Left]);
        assert_eq!(
            tree.lca(&path6),
            Some((
                6,
                Path::new(vec![Direction::Right, Direction::Left])
            ))
        );
    }

    #[test]
    fn test_new_with_depth_zero() {
        // Create a binary tree with depth 0
        let tree = BinaryTree::<IntWrapper>::new_with_depth(0);

        // Define the expected tree: a single root node with no children
        let expected = BinaryTree::<IntWrapper>::new_empty();

        // Assert that the created tree matches the expected tree
        assert_eq!(
            tree.height(),
            expected.height(),
            "A tree with depth 0 should have height 0"
        );
        assert_eq!(
            tree.value, expected.value,
            "A tree with depth 0 should have the same value as an empty tree"
        );
    }

    #[test]
    fn test_new_with_depth_large() {
        // Create a binary tree with a larger depth
        let depth = 4;
        let tree = BinaryTree::<IntWrapper>::new_with_depth(depth);

        // The expected number of nodes for a binary tree of depth d is 2^(d) - 1
        let expected_nodes = (2_usize.pow((depth) as u32)) + 1;
        let actual_nodes = tree.value.len();

        // Assert that the number of nodes matches the expected count
        assert_eq!(
            actual_nodes, expected_nodes,
            "A tree with depth {} should have {} nodes, but found {}",
            depth, expected_nodes, actual_nodes
        );
    }

    #[test]
    fn test_get_all_nodes_along_path() {
        // Create a binary tree for testing:
        //         7
        //        / \
        //       5   6
        //      / \   \
        //     1   2   3
        let tree = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(7)], Path::new(vec![])),
            (
                vec![IntWrapper(7), IntWrapper(5)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(7), IntWrapper(6)],
                Path::new(vec![Direction::Right]),
            ),
            (
                vec![IntWrapper(7), IntWrapper(5), IntWrapper(1)],
                Path::new(vec![Direction::Left, Direction::Left]),
            ),
            (
                vec![IntWrapper(7), IntWrapper(5), IntWrapper(2)],
                Path::new(vec![Direction::Left, Direction::Right]),
            ),
            (
                vec![IntWrapper(7), IntWrapper(6), IntWrapper(3)],
                Path::new(vec![Direction::Right, Direction::Right]),
            ),
        ]);

        // Define paths and their expected node values
        let test_cases = vec![
            // Test case 1: Empty path should return only the root
            (
                Path::new(vec![]),
                vec![IntWrapper(7)],
                "Empty path should return only the root node",
            ),
            // Test case 2: Path to the left child
            (
                Path::new(vec![Direction::Left]),
                vec![IntWrapper(7), IntWrapper(5)],
                "Path [Left] should return the root and left child",
            ),
            // Test case 3: Path to the right child
            (
                Path::new(vec![Direction::Right]),
                vec![IntWrapper(7), IntWrapper(6)],
                "Path [Right] should return the root and right child",
            ),
            // Test case 4: Path to the left-left grandchild
            (
                Path::new(vec![Direction::Left, Direction::Left]),
                vec![IntWrapper(7), IntWrapper(5), IntWrapper(1)],
                "Path [Left, Left] should return the root, left child, and left-left grandchild",
            ),
            // Test case 5: Path to the left-right grandchild
            (
                Path::new(vec![Direction::Left, Direction::Right]),
                vec![IntWrapper(7), IntWrapper(5), IntWrapper(2)],
                "Path [Left, Right] should return the root, left child, and left-right grandchild",
            ),
            // Test case 6: Path to the right-right grandchild
            (
                Path::new(vec![Direction::Right, Direction::Right]),
                vec![IntWrapper(7), IntWrapper(6), IntWrapper(3)],
                "Path [Right, Right] should return the root, right child, and right-right grandchild",
            ),
            // Test case 7: Path that partially exists (non-existent node)
            (
                Path::new(vec![Direction::Right, Direction::Left]),
                vec![IntWrapper(7), IntWrapper(6)],
                "Path [Right, Left] should return only existing nodes up to where the path breaks",
            ),
            // Test case 8: Longer path with non-existent nodes
            (
                Path::new(vec![Direction::Left, Direction::Left, Direction::Left]),
                vec![IntWrapper(7), IntWrapper(5), IntWrapper(1)],
                "Path [Left, Left, Left] should return nodes up to the last existing node",
            ),
        ];

        for (path, expected, description) in test_cases {
            let result = tree.get_all_nodes_along_path(&path);
            assert_eq!(
                result, expected,
                "Failed: {}. Expected {:?}, got {:?}",
                description, expected, result
            );
        }
    }

    #[test]
    fn test_overwrite_tree_basic() {
        // Create the original tree
        // Structure:
        //      1
        //     / \
        //    2   3
        let mut original = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(1)], Path::new(vec![])), // Root
            (
                vec![IntWrapper(1), IntWrapper(2)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(1), IntWrapper(3)],
                Path::new(vec![Direction::Right]),
            ),
        ]);

        // Create the other tree to overwrite with
        // Structure:
        //      4
        //     / \
        //    5   6
        let other = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root
            (
                vec![IntWrapper(4), IntWrapper(5)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(4), IntWrapper(6)],
                Path::new(vec![Direction::Right]),
            ),
        ]);

        // Perform the overwrite
        original.overwrite(&other);

        // Define the expected tree after overwrite
        let expected = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root overwritten
            (
                vec![IntWrapper(4), IntWrapper(5)],
                Path::new(vec![Direction::Left]),
            ), // Left child overwritten
            (
                vec![IntWrapper(4), IntWrapper(6)],
                Path::new(vec![Direction::Right]),
            ), // Right child overwritten
        ]);

        // Assert that the original tree now matches the expected tree
        assert_eq!(
            original, expected,
            "The tree was not correctly overwritten with the other tree"
        );
    }

    #[test]
    fn test_overwrite_tree_with_empty_other() {
        // Create the tree to be overwritten
        let mut original = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(1)], Path::new(vec![])), // Root
            (
                vec![IntWrapper(1), IntWrapper(2)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(1), IntWrapper(3)],
                Path::new(vec![Direction::Right]),
            ),
        ]);

        // Create an empty tree to overwrite with
        let other: BinaryTree<IntWrapper> = BinaryTree::new_empty();

        // Perform the overwrite
        original.overwrite(&other);

        // Define the expected tree after overwrite (should remain unchanged)
        let expected = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(1)], Path::new(vec![])), // Root
            (
                vec![IntWrapper(1), IntWrapper(2)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(1), IntWrapper(3)],
                Path::new(vec![Direction::Right]),
            ),
        ]);

        // Assert that the original tree remains unchanged
        assert_eq!(
            original, expected,
            "Overwriting with an empty tree should not alter the original tree"
        );
    }

    #[test]
    fn test_overwrite_tree_into_empty() {
        // Create the original tree (empty)
        let mut original: BinaryTree<IntWrapper> = BinaryTree::new_empty();

        // Create the other tree to overwrite with
        // Structure:
        //      4
        //     / \
        //    5   6
        let other = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root
            (
                vec![IntWrapper(4), IntWrapper(5)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(4), IntWrapper(6)],
                Path::new(vec![Direction::Right]),
            ),
        ]);

        // Perform the overwrite
        original.overwrite(&other);

        // Define the expected tree after overwrite
        let expected = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root
            (
                vec![IntWrapper(4), IntWrapper(5)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(4), IntWrapper(6)],
                Path::new(vec![Direction::Right]),
            ),
        ]);

        // Assert that the original tree now matches the expected tree
        assert_eq!(
            original, expected,
            "Overwriting an empty tree with another tree should result in the other tree"
        );
    }

    #[test]
    fn test_overwrite_tree_different_structures() {
        // Create the original tree
        // Structure:
        //      1
        //     /
        //    2
        //   /
        //  3
        let mut original = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(1)], Path::new(vec![])), // Root
            (
                vec![IntWrapper(1), IntWrapper(2)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(1), IntWrapper(2), IntWrapper(3)],
                Path::new(vec![Direction::Left, Direction::Left]),
            ),
        ]);

        // Create the other tree to overwrite with
        // Structure:
        //      4
        //       \
        //        5
        //         \
        //          6
        let other = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root
            (
                vec![IntWrapper(4), IntWrapper(5)],
                Path::new(vec![Direction::Right]),
            ),
            (
                vec![IntWrapper(4), IntWrapper(5), IntWrapper(6)],
                Path::new(vec![Direction::Right, Direction::Right]),
            ),
        ]);

        // Perform the overwrite
        original.overwrite(&other);

        // Define the expected tree after overwrite
        let expected = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root overwritten
            (
                vec![IntWrapper(4), IntWrapper(2)],
                Path::new(vec![Direction::Left]),
            ), // Existing left child remains
            (
                vec![IntWrapper(4), IntWrapper(2), IntWrapper(3)],
                Path::new(vec![Direction::Left, Direction::Left]),
            ), // Existing left-left child remains
            (
                vec![IntWrapper(4), IntWrapper(5)],
                Path::new(vec![Direction::Right]),
            ), // Right child added
            (
                vec![IntWrapper(4), IntWrapper(5), IntWrapper(6)],
                Path::new(vec![Direction::Right, Direction::Right]),
            ), // Right-Right child added
        ]);

        // Assert that the original tree now matches the expected tree
        assert_eq!(
            original, expected,
            "Overwriting with a tree of a different structure did not result in the expected tree"
        );
    }

    #[test]
    fn test_overwrite_tree_partial_overlap() {
        // Create the original tree
        // Structure:
        //      1
        //     / \
        //    2   3
        let mut original = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(1)], Path::new(vec![])), // Root
            (
                vec![IntWrapper(1), IntWrapper(2)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(1), IntWrapper(3)],
                Path::new(vec![Direction::Right]),
            ),
        ]);

        // Create the other tree to overwrite with
        // Structure:
        //      4
        //     /
        //    5
        let other = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root
            (
                vec![IntWrapper(4), IntWrapper(5)],
                Path::new(vec![Direction::Left]),
            ), // Overwrites left child
        ]);

        // Perform the overwrite
        original.overwrite(&other);

        // Define the expected tree after overwrite
        let expected = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root overwritten
            (
                vec![IntWrapper(4), IntWrapper(5)],
                Path::new(vec![Direction::Left]),
            ), // Left child overwritten
            (
                vec![IntWrapper(4), IntWrapper(3)],
                Path::new(vec![Direction::Right]),
            ), // Right child remains unchanged
        ]);

        // Assert that the original tree now matches the expected tree
        assert_eq!(
            original, expected,
            "Overwriting with a tree that partially overlaps did not result in the expected tree"
        );
    }
}