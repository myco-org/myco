use std::collections::HashSet;

use crate::{tree::BinaryTree, Bucket, Key, Path, D, DELTA};

pub struct Server2 {
    pub(crate) tree: BinaryTree<Bucket>,
    pub(crate) prf_keys: Vec<Key>,
    pub(crate) epoch: u64,
}

impl Server2 {
    pub fn new() -> Self {
        let mut tree = BinaryTree::new_with_depth(D);
        tree.fill(Bucket::default());

        Server2 {
            tree,
            prf_keys: vec![],
            epoch: 0,
        }
    }

    /// l is the leaf block.
    pub fn read(&mut self, l: &Path) -> Vec<Bucket> {
        self.tree.get_all_nodes_along_path(l)
    }

    /// Update the tree in S2 with the pt from S1 for epoch.
    pub fn write(&mut self, pt: BinaryTree<Bucket>, pathset: Vec<Path>) {
        // Get the unique indices of all nodes in the pathset.
        let pathset_indices_set: HashSet<usize> =
            pathset.iter().flat_map(|path| path.get_indices()).collect();

        // If the index is in the pathset, insert the bucket from pt into self.tree
        for (i, bucket) in pt.value.iter().enumerate() {
            if pathset_indices_set.contains(&i) {
                self.tree.value[i] = bucket.clone();
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
}
