use crate::{constants::*, Block};
use rand::Rng;

pub struct Server2 {
    pub tree: Vec<Vec<Block>>,
}

impl Server2 {
    pub fn new() -> Self {
        let mut tree = Vec::new();
        for _ in 0..TREE_HEIGHT {
            let level: Vec<Block> = Vec::new();
            tree.push(level);
        }
        Server2 { tree }
    }

    pub fn read(&self, l: &[u8]) -> Vec<Block> {
        let mut path = Vec::new();
        for level in (0..TREE_HEIGHT).rev() {
            let bucket = &self.tree[level];
            path.extend(
                bucket
                    .iter()
                    .filter(|block| !block.data.is_empty())
                    .cloned(),
            );
        }
        path
    }

    pub fn write(&mut self, blocks: Vec<Block>) {
        for block in blocks {
            let leaf = &block.bid[..32];
            let mut index = self.leaf_to_index(leaf);
            for level in (0..TREE_HEIGHT).rev() {
                let bucket = &mut self.tree[level];
                if bucket.len() < BUCKET_SIZE {
                    bucket.push(block.clone());
                    break;
                }
                // If bucket is full, continue to the next level
                index /= 2;
            }
        }
    }

    fn leaf_to_index(&self, leaf: &[u8]) -> usize {
        let mut index = 0;
        for &byte in leaf.iter().take(4) {
            index = (index << 8) | byte as usize;
        }
        index % (1 << (TREE_HEIGHT - 1))
    }

    pub fn evict(&mut self) {
        for _ in 0..EVICTION_RATE {
            let leaf: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
            let mut index = self.leaf_to_index(&leaf);
            let mut blocks_to_push = Vec::new();

            for level in 0..TREE_HEIGHT {
                let mut new_bucket = Vec::new();
                let bucket = std::mem::take(&mut self.tree[level]);

                for block in bucket {
                    let block_index = self.leaf_to_index(&block.bid);
                    if block_index == index {
                        blocks_to_push.push(block);
                    } else {
                        new_bucket.push(block);
                    }
                }

                self.tree[level] = new_bucket;
                index /= 2;
            }

            self.write(blocks_to_push);
        }
    }
}