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

    /// l is the leaf block
    pub fn read(&self, l: &Path) -> Vec<Bucket> {
        self.tree.get_all_nodes_along_path(l)
    }

    pub fn read_paths(&self, paths: Vec<Path>) -> (Vec<Bucket>, Vec<usize>) {
        let mut pathset: HashSet<usize> = HashSet::new();
        pathset.insert(1);
        paths.iter().for_each(|p| {
            p.clone().into_iter().fold(1, |acc, d| {
                let idx = 2 * acc + u8::from(d) as usize;
                if idx >= self.tree.value.len() || self.tree.value[idx].is_none() {
                    return acc;
                }
                pathset.insert(idx);
                idx
            });
        });

        let buckets = pathset
            .iter()
            .map(|i| self.tree.value[*i].clone().unwrap())
            .collect();
        let idx = pathset.iter().map(|i| *i).collect();

        (buckets, idx)
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
