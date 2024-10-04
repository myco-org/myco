use std::collections::HashMap;

use crate::{Block, Key, Path};

pub struct Server2 {
    pathset: HashMap<Path, Vec<Block>>,
    prf_keys: Vec<Key>,
}

impl Server2 {
    pub fn new() -> Self {
        Server2 {
            pathset: HashMap::new(),
            prf_keys: vec![],
        }
    }

    /// l is the leaf block
    pub fn read(&self, l: &Path) -> Vec<Block> {
        self.pathset.get(l).cloned().unwrap_or_default()
    }

    pub fn write(&mut self, blocks: Vec<(Path, Vec<Block>)>) {
        let mut pathset = HashMap::new();
        for (path, blocks) in blocks {
            pathset.insert(path, blocks);
        }
        self.pathset = pathset;
    }

    pub fn get_prf_keys(&self) -> Vec<Key> {
        self.prf_keys.clone()
    }

    pub fn add_prf_keys(&mut self, key: Key) {
        self.prf_keys.push(key);
        self.prf_keys.remove(0);
    }
}
