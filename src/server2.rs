use crate::{tree::BinaryTree, Bucket, Key, Path, D, DELTA};

pub struct Server2 {
    pub(crate) tree: BinaryTree<Bucket>,
    pub(crate) prf_keys: Vec<Key>,
    pub(crate) epoch: u64,
}

impl Server2 {
    pub fn new() -> Self {
        Server2 {
            tree: BinaryTree::new_with_depth(D),
            prf_keys: vec![],
            epoch: 0,
        }
    }

    /// l is the leaf block
    pub fn read(&self, l: &Path) -> Vec<Bucket> {
        self.tree.get_all_nodes_along_path(l)
    }

    pub fn write(&mut self, pathset: BinaryTree<Bucket>) {
        self.tree = pathset;
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
