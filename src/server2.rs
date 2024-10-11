use crate::{tree::BinaryTree, Block, Key, Path};

pub struct Server2 {
    pathset: BinaryTree<Vec<Block>>,
    prf_keys: Vec<Key>,
}

impl Server2 {
    pub fn new() -> Self {
        Server2 {
            pathset: BinaryTree::new(vec![]),
            prf_keys: vec![],
        }
    }

    /// l is the leaf block
    pub fn read(&self, l: &Path) -> Vec<Block> {
        self.pathset.get(l).cloned().unwrap_or_default()
    }

    pub fn write(&mut self, pathset: BinaryTree<Vec<Block>>) {
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
