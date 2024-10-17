use crate::{tree::BinaryTree, Block, Bucket, Key, Path, D};

pub struct Server2 {
    pub(crate) pathset: BinaryTree<Bucket>,
    pub(crate) prf_keys: Vec<Key>,
}

impl Server2 {
    pub fn new() -> Self {
        Server2 {
            pathset: BinaryTree::new_with_depth(D),
            prf_keys: vec![],
        }
    }

    /// l is the leaf block
    pub fn read(&self, l: &Path) -> Vec<Bucket> {
        self.pathset.get_all_nodes_along_path(l)
    }

    pub fn write(&mut self, pathset: BinaryTree<Bucket>) {
        self.pathset = pathset;
    }

    pub fn get_prf_keys(&self) -> Vec<Key> {
        self.prf_keys.clone()
    }

    pub fn add_prf_keys(&mut self, key: &Key) {
        self.prf_keys.push(key.clone());
        self.prf_keys.remove(0);
    }
}
