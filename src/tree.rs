use std::{
    cmp::max,
    fmt::{self, Debug},
    fs::File,
    io::{Read, Write},
    sync::RwLock,
};

use aes_gcm::aead::Buffer;
use serde::{Deserialize, Serialize};

use crate::{Bucket, Direction, Metadata, Path};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BinaryTree<T> {
    pub value: Vec<Option<T>>,
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
            // Prev 1 << depth + 1
            // For a binary tree of depth d, the number of nodes is 2^(d+1) - 1. However, we ignore the zero index, and instead represent the root node as index 1.
            // This is for simpler calculation.
            value: vec![None; 1 << (depth + 1)],
        }
    }

    pub fn fill(&mut self, value: T) {
        self.value[1..].fill(Some(value));
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
        ((self.value.len() as f64).log2().ceil() as usize) - 1
    }

    pub fn from_array(values: Vec<T>, indices: Vec<usize>) -> Self {
        let mut tree = BinaryTree::new_empty();
        for (value, index) in values.iter().zip(indices) {
            if index >= tree.value.len() {
                tree.value.resize((index + 1).next_power_of_two(), None);
            }
            tree.value[index] = Some(value.clone());
        }
        tree
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

    pub fn get_index(&self, path: &Path) -> usize {
        let mut current = 1;
        let mut idx = 1;
        for &direction in path {
            idx = 2 * idx + u8::from(direction) as usize;
            if idx >= self.value.len() {
                return 1;
            }
            current = idx;
        }
        idx
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

    pub fn lca_idx(&self, path: &Path) -> Option<(usize, Path)> {
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

    pub fn lca(&mut self, path: &Path) -> Option<(&mut T, Path)> {
        let mut current_path = Path::new(Vec::new());
        let mut idx = 1;

        for &direction in path {
            let next_idx = 2 * idx + u8::from(direction) as usize;
            if next_idx >= self.value.len() || self.value[next_idx].is_none() {
                return self.value[idx].as_mut().map(|value| (value, current_path));
            }
            idx = next_idx;
            current_path.push(direction);
        }

        self.value[idx].as_mut().map(|value| (value, current_path))
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

    pub fn overwrite_from_sparse(&mut self, sparse_tree: &SparseBinaryTree<T>) {
        // Ensure that the binary tree has enough capacity to hold the elements from the sparse tree
        if let Some(&max_index) = sparse_tree.packed_indices.iter().max() {
            if max_index >= self.value.len() {
                self.value.resize(max_index + 1, None);
            }
        }

        // Iterate over the sparse tree and copy its values into the binary tree at the corresponding indices
        for (bucket, &index) in sparse_tree
            .packed_buckets
            .iter()
            .zip(&sparse_tree.packed_indices)
        {
            self.value[index] = Some(bucket.clone());
        }
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

    pub fn zip_mut<'a, 'b, S>(
        &'a mut self,
        rhs: &'b mut BinaryTree<S>,
    ) -> Vec<(Option<&'a mut T>, Option<&'b mut S>, Path)> {
        let len = std::cmp::max(self.value.len(), rhs.value.len());

        // Ensure both trees have the same size by resizing them
        self.value.resize_with(len, || None);
        rhs.value.resize_with(len, || None);

        // Iterate over both trees, returning mutable references
        self.value
            .iter_mut()
            .zip(rhs.value.iter_mut())
            .enumerate()
            .filter_map(|(i, (a, b))| {
                if a.is_some() {
                    Some((a.as_mut(), b.as_mut(), Path::from(i)))
                } else {
                    None
                }
            })
            .collect()
    }
}

impl fmt::Display for BinaryTree<Bucket> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Binary Tree:")?;
        write!(f, "[")?;
        for (i, bucket) in self.value.iter().enumerate() {
            let bucket_len = bucket.as_ref().map_or(0, |b| b.len());
            write!(f, "{}", bucket_len)?;
            if i < self.value.len() - 1 {
                write!(f, ", ")?;
            }
        }
        write!(f, "]")
    }
}

// Sparse binary tree

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SparseBinaryTree<T> {
    pub packed_buckets: Vec<T>,     // List of non-None buckets
    pub packed_indices: Vec<usize>, // Indices corresponding to these buckets
}

impl<T> SparseBinaryTree<T>
where
    T: Clone + Debug + PartialEq + Default,
{
    // Creates a new empty sparse binary tree
    pub fn new() -> Self {
        SparseBinaryTree {
            packed_buckets: Vec::new(),
            packed_indices: Vec::new(),
        }
    }

    // Creates a new sparse binary tree with provided packed_buckets and packed_indices
    pub fn new_with_data(packed_buckets: &[T], packed_indices: &[usize]) -> Self {
        SparseBinaryTree {
            packed_buckets: packed_buckets.to_vec(),
            packed_indices: packed_indices.to_vec(),
        }
    }

    // Helper function to add a bucket and its index
    fn add_bucket(&mut self, index: usize, value: T) {
        // Check if the index already exists
        if let Some(pos) = self.packed_indices.iter().position(|&i| i == index) {
            // If it exists, replace the corresponding value in packed_buckets
            self.packed_buckets[pos] = value;
        } else {
            // Otherwise, add the new value and index
            self.packed_buckets.push(value);
            self.packed_indices.push(index);
        }
    }

    // Retrieve the value at the given path in a sparse binary tree
    pub fn get(&self, path: &Path) -> Option<&T> {
        let mut idx = 1; // Start at the root
        for &direction in path {
            idx = 2 * idx + u8::from(direction) as usize;
        }
        self.get_by_index(idx)
    }

    // Retrieve the value at the given path in a sparse binary tree
    pub fn get_index(&self, path: &Path) -> usize {
        let mut idx = 1; // Start at the root
        for &direction in path {
            idx = 2 * idx + u8::from(direction) as usize;
        }
        idx
    }

    // Retrieves value by index
    pub fn get_by_index(&self, index: usize) -> Option<&T> {
        self.packed_indices
            .iter()
            .position(|&i| i == index)
            .map(|pos| &self.packed_buckets[pos])
    }

    // Retreives a reference to the bucket by index
    pub fn get_by_index_mut(&mut self, index: usize) -> Option<&mut T> {
        self.packed_indices
            .iter()
            .position(|&i| i == index)
            .map(move |pos| &mut self.packed_buckets[pos]) // Returns mutable reference
    }

    // Write a value into the sparse tree at the specified path
    pub fn write(&mut self, value: T, path: Path) {
        let mut idx = 1; // Start at the root

        for direction in path {
            idx = 2 * idx + u8::from(direction) as usize;
        }

        self.add_bucket(idx, value);
    }

    // Find the lowest common ancestor (LCA) of a given path
    pub fn lca_idx(&self, path: &Path) -> Option<(usize, Path)> {
        let mut current_path = Path::new(Vec::new());
        let mut idx = 1; // Start at the root

        for &direction in path {
            let next_idx = 2 * idx + u8::from(direction) as usize;
            if self.get_by_index(next_idx).is_none() {
                // Get the index of next_idx in the array.
                let next_idx_index = self
                    .packed_indices
                    .iter()
                    .position(|&i| i == next_idx)
                    .unwrap();
                return Some((next_idx_index, current_path));
            }
            idx = next_idx;
            current_path.push(direction);
        }

        Some((idx, current_path))
    }

    // Find the lowest common ancestor (LCA) of a given path
    pub fn lca(&mut self, path: &Path) -> Option<(&mut T, Path)> {
        let mut current_path = Path::new(Vec::new());
        let mut idx = 1; // Start at the root

        for &direction in path {
            let next_idx = 2 * idx + u8::from(direction) as usize;
            if self.get_by_index(next_idx).is_none() {
                return self
                    .get_by_index_mut(idx) // Get mutable reference here
                    .map(|value| (value, current_path.clone()));
            }
            idx = next_idx;
            current_path.push(direction);
        }

        self.get_by_index_mut(idx) // Get mutable reference at the end
            .map(|value| (value, current_path.clone()))
    }

    // // Overwrite the sparse binary tree with another one
    // pub fn overwrite(&mut self, other: &SparseBinaryTree<T>) {
    //     for (index, bucket) in other.indices.iter().zip(&other.packed_buckets) {
    //         self.add_bucket(*index, bucket.clone());
    //     }
    // }

    // Zips two sparse binary trees together
    pub fn zip<S: Clone>(&self, rhs: &SparseBinaryTree<S>) -> Vec<(Option<T>, Option<S>, Path)> {
        let mut results = Vec::new();

        let max_len = self.packed_indices.len().max(rhs.packed_indices.len());

        for i in 0..max_len {
            let lhs_bucket = self.packed_buckets.get(i).cloned();
            let rhs_bucket = rhs.packed_buckets.get(i).cloned();

            if let Some(lhs_index) = self.packed_indices.get(i) {
                let path = Path::from(*lhs_index);
                results.push((lhs_bucket, rhs_bucket, path));
            }
        }

        results
    }

    pub fn zip_with_binary_tree<S: Clone>(
        &self,
        rhs: &BinaryTree<S>,
    ) -> Vec<(Option<T>, Option<S>, Path)> {
        let mut results = Vec::new();

        // Iterate only over the indices in the sparse binary tree
        for (i, &index) in self.packed_indices.iter().enumerate() {
            let lhs_bucket = self.packed_buckets.get(i).cloned(); // Get the value from the sparse tree

            // Get the corresponding value from the normal binary tree
            let rhs_bucket = if index < rhs.value.len() {
                rhs.value[index].clone()
            } else {
                None
            };

            // Create a Path from the current index
            let path = Path::from(index);

            // Add the zipped result to the results vector
            results.push((lhs_bucket, rhs_bucket, path));
        }

        results
    }

    pub fn zip_mut<'a, 'b, S>(
        &'a mut self,
        rhs: &'b mut SparseBinaryTree<S>,
    ) -> Vec<(Option<&'a mut T>, Option<&'b mut S>, Path)> {
        // Ensure both trees have the same number of elements
        if self.packed_indices.len() != rhs.packed_indices.len() {
            panic!("Trees must have the same number of elements to zip.");
        }

        let mut result = Vec::new();

        for i in 0..self.packed_indices.len() {
            let lhs_idx = self.packed_indices[i];
            let rhs_idx = rhs.packed_indices[i];

            if lhs_idx == rhs_idx {
                // SAFETY: We know `i` is in bounds due to the length check above.
                let lhs_value = &mut self.packed_buckets[i] as *mut T;
                let rhs_value = &mut rhs.packed_buckets[i] as *mut S;

                unsafe {
                    result.push((
                        Some(&mut *lhs_value),
                        Some(&mut *rhs_value),
                        Path::from(lhs_idx),
                    ));
                }
            } else {
                // The indices don't match, this case shouldn't happen given the assumption
                panic!("Indices don't match in the same-length trees.");
            }
        }

        result
    }
}

#[derive(Serialize, Deserialize)]
struct DBState {
    tree: BinaryTree<Bucket>,
    metadata: BinaryTree<Metadata>,
}

/// Parameters that define the state of the DB.
pub struct DBStateParams {
    pub bucket_size: usize,
    pub num_iters: usize,
    pub depth: usize,
    pub num_clients: usize,
    pub timestamp: u64,
}

/// Serialize the trees into a file.
///
/// State is saved in the format state_{bucket_size}_{num_iters}_{depth}_{num_clients}.bin to db/
pub fn save_trees(
    tree: &BinaryTree<Bucket>,
    metadata: &BinaryTree<Metadata>,
    params: &DBStateParams,
) {
    let db_state = DBState {
        tree: tree.clone(),
        metadata: metadata.clone(),
    };
    let serialized_db_state = bincode::serialize(&db_state).unwrap();
    let dir_path = format!(
        "db/state_{}_{}_{}_{}",
        params.bucket_size, params.num_iters, params.depth, params.num_clients
    );
    std::fs::create_dir_all(&dir_path).unwrap();
    let file_path = format!("{}/{}.bin", dir_path, params.timestamp);
    let mut file = File::create(file_path).unwrap();
    file.write_all(&serialized_db_state).unwrap();
}

/// Deserialize the trees from a file.
pub fn desave_trees(params: &DBStateParams) -> (BinaryTree<Bucket>, BinaryTree<Metadata>) {
    let mut file = File::open(format!(
        "db/state_{}_{}_{}_{}/{}.bin",
        params.bucket_size, params.num_iters, params.depth, params.num_clients, params.timestamp
    ))
    .unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();

    let db_state: DBState = bincode::deserialize(&buffer).unwrap();

    (db_state.tree, db_state.metadata)
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};
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
        let mut tree = BinaryTree::from_vec_with_paths(items);

        // Test lca with various paths
        let path1 = Path::new(vec![Direction::Left, Direction::Left]);
        assert_eq!(tree.lca(&path1), Some((&mut IntWrapper(1), path1.clone())));

        let path2 = Path::new(vec![Direction::Right, Direction::Right]);
        assert_eq!(tree.lca(&path2), Some((&mut IntWrapper(4), path2.clone())));

        let path3 = Path::new(vec![]);
        assert_eq!(tree.lca(&path3), Some((&mut IntWrapper(7), path3.clone())));

        let path4 = Path::new(vec![Direction::Left]);
        assert_eq!(tree.lca(&path4), Some((&mut IntWrapper(5), path4.clone())));

        let path5 = Path::new(vec![Direction::Left, Direction::Right, Direction::Left]);
        assert_eq!(
            tree.lca(&path5),
            Some((
                &mut IntWrapper(2),
                Path::new(vec![Direction::Left, Direction::Right])
            ))
        );

        let path6 = Path::new(vec![Direction::Right, Direction::Left, Direction::Left]);
        assert_eq!(
            tree.lca(&path6),
            Some((
                &mut IntWrapper(3),
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
        let expected_nodes = (2_usize.pow((depth + 1) as u32));
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
