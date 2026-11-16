pub mod myco;

use crate::dtypes::{Path, TreeMycoKey};
use crate::tree::SparseBinaryTree;
use crate::dtypes::{Block, Bucket, Key};

impl From<Bucket> for myco::Bucket {
    fn from(b: Bucket) -> Self {
        Self {
            data: b.iter().flat_map(|block| block.0.clone()).collect(),
            signature: b.1.clone().unwrap_or_default(),
        }
    }
}

impl From<&Bucket> for myco::Bucket {
    fn from(b: &Bucket) -> Self {
        Self {
            data: b.iter().flat_map(|block| block.0.clone()).collect(),
            signature: b.1.clone().unwrap_or_default(),
        }
    }
}

impl From<myco::Bucket> for Bucket {
    fn from(b: myco::Bucket) -> Self {
        let notif_block_size: usize = crate::constants::LAMBDA_BYTES;
        let chunk_size = if b.data.len() % notif_block_size == 0
            && (b.data.len() / notif_block_size) <= crate::constants::Z_M
        {
            notif_block_size
        } else {
            crate::constants::BLOCK_SIZE
        };
        let mut blocks = Vec::new();
        // Split b.data into chunks using the chosen chunk size.
        for block_data in b.data.chunks(chunk_size) {
            blocks.push(Block::new(block_data.to_vec()));
        }
        // Preserve the signature from the proto bucket if it's non-empty.
        let signature = if b.signature.is_empty() {
            None
        } else {
            Some(b.signature)
        };
        Bucket(blocks, signature)
    }
}

impl myco::Bucket {
    /// Converts a wire bucket into the form Server2 stores (see [`Bucket::contiguous`]).
    pub fn into_stored(self) -> Bucket {
        let signature = if self.signature.is_empty() {
            None
        } else {
            Some(self.signature)
        };
        Bucket::contiguous(self.data, signature)
    }
}

impl From<Key<TreeMycoKey>> for myco::Key {
    fn from(k: Key<TreeMycoKey>) -> Self {
        Self {
            data: k.bytes.clone(),
        }
    }
}

impl From<myco::Key> for Key<TreeMycoKey> {
    fn from(k: myco::Key) -> Self {
        Key::new(k.data)
    }
}

impl From<Vec<myco::Bucket>> for SparseBinaryTree<Bucket> {
    fn from(buckets: Vec<myco::Bucket>) -> Self {
        let mut tree = SparseBinaryTree::new();
        for (i, bucket) in buckets.into_iter().enumerate() {
            tree.write(bucket.into(), Path::from(i));
        }
        tree
    }
}
