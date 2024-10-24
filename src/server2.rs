use std::collections::HashSet;

use crate::{tree::BinaryTree, Bucket, Key, Path, D, DELTA};

pub struct Server2 {
    pub(crate) tree: BinaryTree<Bucket>,
    pub(crate) prf_keys: Vec<Key>,
    pub(crate) epoch: u64,
    pathset_indices: Vec<usize>
}

impl Server2 {
    pub fn new() -> Self {
        let mut tree = BinaryTree::new_with_depth(D);
        tree.fill(Bucket::default());

        Server2 {
            tree,
            prf_keys: vec![],
            epoch: 0,
            pathset_indices: vec![]
        }
    }

    /// l is the leaf block.
    pub fn read(&mut self, l: &Path) -> Vec<Bucket> {
        self.tree.get_all_nodes_along_path(l)
    }

    pub fn write(&mut self, pt: BinaryTree<Bucket>) {
        // Iterate over the indices in self.pathset_indices and use them to overwrite corresponding values in self.tree
        for &index in self.pathset_indices.iter() {
            if let Some(bucket) = pt.value.get(index) {
                self.tree.value[index] = bucket.clone();
            }
        }
    
        self.epoch += 1;
    }    
    
    pub fn get_prf_keys(&self) -> Vec<Key> {
        self.prf_keys.clone()
    }

    pub fn add_prf_keys(&mut self, key: &Key) {
        self.prf_keys.push(key.clone());

        if self.epoch >= DELTA {
            self.prf_keys.remove(0);
        }
    }

    pub fn read_paths(&mut self, pathset: Vec<usize>) -> (Vec<Bucket>) {
        self.pathset_indices = pathset.clone();

        let buckets = pathset
            .iter()
            .map(|i| self.tree.value[*i].clone().unwrap())
            .collect();
        buckets
    }
}
