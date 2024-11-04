use std::{
    cmp::max,
    fmt::{self, Debug},
    fs::File,
    io::{Read, Write},
    time::Instant,
};

use aes_gcm::aead::Buffer;
use serde::{Deserialize, Serialize};

use crate::{Bucket, Direction, Metadata, Path};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BinaryTree<T> {
    pub value: Vec<Option<T>>,
}

pub trait TreeValue: Clone + Debug + PartialEq + Default {
    fn new_random() -> Self;
}

impl<T: TreeValue> BinaryTree<T> {
    pub fn new(value: T) -> Self {
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
        let start = Instant::now();

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
    pub fn new_with_data(packed_buckets: Vec<T>, packed_indices: Vec<usize>) -> Self {
        SparseBinaryTree {
            packed_buckets,
            packed_indices,
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
                return Some((idx, current_path.clone()));
            }
            idx = next_idx;
            current_path.push(direction);
        }
        Some((idx, current_path.clone()))
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

    pub fn get_all_nodes_along_path(&self, path: &Path) -> Vec<&T> {
        let mut nodes = Vec::new();
        let mut idx = 1;  // Start at root

        // Check root
        if let Some(value) = self.get_by_index(idx) {
            nodes.push(value);
        }

        // Check each node along the path
        for &direction in path {
            idx = 2 * idx + u8::from(direction) as usize;
            if let Some(value) = self.get_by_index(idx) {
                nodes.push(value);
            }
        }

        nodes
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
pub fn serialize_trees(
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
pub fn deserialize_trees(params: &DBStateParams) -> (BinaryTree<Bucket>, BinaryTree<Metadata>) {
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

