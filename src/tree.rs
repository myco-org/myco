use crate::Path;
use std::fmt;
use crate::Direction;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BinaryTree<T> {
    value: Option<T>,
    left: Option<Box<BinaryTree<T>>>,
    right: Option<Box<BinaryTree<T>>>,
}

impl<T> BinaryTree<T> {
    pub(crate) fn new(value: T) -> Self {
        BinaryTree { value: Some(value), left: None, right: None }
    }

    pub fn new_empty() -> Self {
        BinaryTree { value: None, left: None, right: None }
    }

    pub fn from_vec_with_paths(items: Vec<(T, Path)>) -> Self
    where
        T: Clone + Default,
    {
        if items.is_empty() {
            return BinaryTree::new_empty();
        }

        let mut root = BinaryTree::new_empty();

        for (value, path) in items {
            let mut current = &mut root;

            for &direction in &path {
                match direction {
                    Direction::Left => {
                        if current.left.is_none() {
                            current.left = Some(Box::new(BinaryTree::new_empty()));
                        }
                        current = current.left.as_mut().unwrap();
                    }
                    Direction::Right => {
                        if current.right.is_none() {
                            current.right = Some(Box::new(BinaryTree::new_empty()));
                        }
                        current = current.right.as_mut().unwrap();
                    }
                }
            }

            current.value = Some(value);
        }

        root
    }

    pub fn height(&self) -> usize {
        fn calculate_height<T>(node: &Option<Box<BinaryTree<T>>>) -> usize {
            match node {
                Some(n) => {
                    let left_height = calculate_height(&n.left);
                    let right_height = calculate_height(&n.right);
                    1 + left_height.max(right_height)
                }
                None => 0,
            }
        }

        let left_height = calculate_height(&self.left);
        let right_height = calculate_height(&self.right);
        left_height.max(right_height)
    }

    pub fn get_leaf(&self, index: usize) -> Option<&T> {
        let height = self.height();
        if index >= (1 << height) {
            return None;
        }
        let mut current = self;
        let mut path = vec![];

        for i in (0..height).rev() {
            let bit = (index >> i) & 1;
            path.push(if bit == 0 { Direction::Left } else { Direction::Right });
        }

        for direction in path {
            match direction {
                Direction::Left => {
                    if let Some(left) = &current.left {
                        current = left;
                    } else {
                        return None;
                    }
                }
                Direction::Right => {
                    if let Some(right) = &current.right {
                        current = right;
                    } else {
                        return None;
                    }
                }
            }
        }

        current.value.as_ref()
    }

    pub fn get(&self, path: &Path) -> Option<&T> {
        let mut current = self;
        for direction in path {
            match direction {
                Direction::Left => {
                    current = current.left.as_ref()?;
                }
                Direction::Right => {
                    current = current.right.as_ref()?;
                }
            }
        }

        current.value.as_ref()
    }

    pub fn lca(&self, path: &Path) -> Option<(&T, Path)> {
        let mut current = self;
        let mut current_path = Path::new(Vec::new());
        
        for &direction in path {
            match direction {
                Direction::Left => {
                    if let Some(left) = &current.left {
                        current = left;
                        current_path.push(Direction::Left);
                    } else {
                        // Cannot continue down path, return current node and path
                        return current.value.as_ref().map(|v| (v, current_path));
                    }
                }
                Direction::Right => {
                    if let Some(right) = &current.right {
                        current = right;
                        current_path.push(Direction::Right);
                    } else {
                        // Cannot continue down path, return current node and path
                        return current.value.as_ref().map(|v| (v, current_path));
                    }
                }
            }
            
            // If we've reached a leaf node, return it and the path
            if current.left.is_none() && current.right.is_none() {
                return current.value.as_ref().map(|v| (v, current_path));
            }
        }
        
        // If we've exhausted path, return the last node and the path
        current.value.as_ref().map(|v| (v, current_path))
    }

    pub fn write(&mut self, value: T, path: Path) {
        let mut current = self;
        for direction in path {
            match direction {
                Direction::Left => {
                    if current.left.is_none() {
                        current.left = Some(Box::new(BinaryTree::new_empty()));
                    }
                    current = current.left.as_mut().unwrap();
                }
                Direction::Right => {
                    if current.right.is_none() {
                        current.right = Some(Box::new(BinaryTree::new_empty()));
                    }
                    current = current.right.as_mut().unwrap();
                }
            }
        }
    
        current.value = Some(value);
    }
}

impl<T: fmt::Debug> fmt::Display for BinaryTree<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn print_tree<T: fmt::Debug>(
            node: &BinaryTree<T>,
            f: &mut fmt::Formatter<'_>,
            prefix: &str,
            is_left: bool,
        ) -> fmt::Result {
            if is_left {
                writeln!(f, "{}├─ {:?}", prefix, node.value)?;
            } else {
                writeln!(f, "{}└─ {:?}", prefix, node.value)?;
            }

            let new_prefix = if is_left {
                format!("{}│ ", prefix)
            } else {
                format!("{}  ", prefix)
            };

            if let Some(left) = &node.left {
                print_tree(left, f, &new_prefix, true)?;
            }
            if let Some(right) = &node.right {
                print_tree(right, f, &new_prefix, false)?;
            }

            Ok(())
        }

        print_tree(self, f, "", false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_small_binary_tree() {
        // Test creating a new tree
        let tree = BinaryTree::new(1);
        assert_eq!(tree.value, Some(1));
        assert!(tree.left.is_none());
        assert!(tree.right.is_none());

        // Test from_vec_with_paths for a small tree
        let small_items = vec![
            (1, Path::new(vec![Direction::Left, Direction::Left])),
            (2, Path::new(vec![Direction::Left, Direction::Right])),
            (3, Path::new(vec![Direction::Right, Direction::Left])),
            (4, Path::new(vec![Direction::Right, Direction::Right])),
        ];
        let small_tree = BinaryTree::from_vec_with_paths(small_items);
        println!("Small tree:\n{}", small_tree);

        // Test get method for small tree
        assert_eq!(small_tree.get_leaf(0), Some(&1));
        assert_eq!(small_tree.get_leaf(1), Some(&2));
        assert_eq!(small_tree.get_leaf(2), Some(&3));
        assert_eq!(small_tree.get_leaf(3), Some(&4));
        assert_eq!(small_tree.get_leaf(4), None);
    }

    #[test]
    fn test_large_binary_tree() {
        // Test from_vec_with_paths for a larger tree with height 4 and some null values
        let large_items = vec![
            (1, Path::new(vec![Direction::Left, Direction::Left, Direction::Left, Direction::Left])),
            (2, Path::new(vec![Direction::Left, Direction::Left, Direction::Right, Direction::Right])),
            (3, Path::new(vec![Direction::Left, Direction::Right, Direction::Left, Direction::Left])),
            (4, Path::new(vec![Direction::Right, Direction::Left, Direction::Left, Direction::Left])),
            (5, Path::new(vec![Direction::Right, Direction::Left, Direction::Right, Direction::Right])),
            (6, Path::new(vec![Direction::Right, Direction::Right, Direction::Left, Direction::Left])),
            (7, Path::new(vec![Direction::Right, Direction::Right, Direction::Right, Direction::Left])),
            (8, Path::new(vec![Direction::Right, Direction::Right, Direction::Right, Direction::Right])),
        ];
        let large_tree = BinaryTree::from_vec_with_paths(large_items);
        println!("Large tree:\n{}", large_tree);

        // Test get method for large tree
        assert_eq!(large_tree.get_leaf(0), Some(&1));
        assert_eq!(large_tree.get_leaf(3), Some(&2));
        assert_eq!(large_tree.get_leaf(4), Some(&3));
        assert_eq!(large_tree.get_leaf(8), Some(&4));
        assert_eq!(large_tree.get_leaf(11), Some(&5));
        assert_eq!(large_tree.get_leaf(12), Some(&6));
        assert_eq!(large_tree.get_leaf(14), Some(&7));
        assert_eq!(large_tree.get_leaf(15), Some(&8));

        // Test null values
        assert_eq!(large_tree.get_leaf(1), None);
        assert_eq!(large_tree.get_leaf(2), None);
        assert_eq!(large_tree.get_leaf(5), None);
        assert_eq!(large_tree.get_leaf(6), None);
        assert_eq!(large_tree.get_leaf(7), None);
        assert_eq!(large_tree.get_leaf(9), None);
        assert_eq!(large_tree.get_leaf(10), None);
        assert_eq!(large_tree.get_leaf(13), None);
    }

    #[test]
    fn test_get() {
        // Create a tree with some values, including non-leaf nodes
        let items = vec![
            (1, Path::new(vec![Direction::Left, Direction::Left])),
            (2, Path::new(vec![Direction::Left, Direction::Right])),
            (3, Path::new(vec![Direction::Right, Direction::Left])),
            (4, Path::new(vec![Direction::Right, Direction::Right])),
            (5, Path::new(vec![Direction::Left])),  // Non-leaf node
            (6, Path::new(vec![Direction::Right])), // Non-leaf node
            (7, Path::new(vec![])),                 // Root node
        ];
        let tree = BinaryTree::from_vec_with_paths(items);
        println!("Tree:\n{}", tree);

        // Test get method for existing paths (including non-leaf nodes)
        assert_eq!(tree.get(&Path::new(vec![Direction::Left, Direction::Left])), Some(&1));
        assert_eq!(tree.get(&Path::new(vec![Direction::Left, Direction::Right])), Some(&2));
        assert_eq!(tree.get(&Path::new(vec![Direction::Right, Direction::Left])), Some(&3));
        assert_eq!(tree.get(&Path::new(vec![Direction::Right, Direction::Right])), Some(&4));
        assert_eq!(tree.get(&Path::new(vec![Direction::Left])), Some(&5));
        assert_eq!(tree.get(&Path::new(vec![Direction::Right])), Some(&6));
        assert_eq!(tree.get(&Path::new(vec![])), Some(&7));

        // Test get method for non-existing paths
        assert_eq!(tree.get(&Path::new(vec![Direction::Left, Direction::Left, Direction::Left])), None);
        assert_eq!(tree.get(&Path::new(vec![Direction::Right, Direction::Right, Direction::Right])), None);
        assert_eq!(tree.get(&Path::new(vec![Direction::Left, Direction::Left, Direction::Right])), None);
        assert_eq!(tree.get(&Path::new(vec![Direction::Right, Direction::Left, Direction::Right])), None);
    }

    #[test]
    fn test_lca() {
        // Create a binary tree:
        //         7
        //        / \
        //       5   6
        //      / \ / \
        //     1  2 3 4

        let items = vec![
            (7, Path::new(vec![])), // Root node
            (5, Path::new(vec![Direction::Left])),
            (6, Path::new(vec![Direction::Right])),
            (1, Path::new(vec![Direction::Left, Direction::Left])),
            (2, Path::new(vec![Direction::Left, Direction::Right])),
            (3, Path::new(vec![Direction::Right, Direction::Left])),
            (4, Path::new(vec![Direction::Right, Direction::Right])),
        ];
        let tree = BinaryTree::from_vec_with_paths(items);

        // Test lca with various paths
        // Case 1: Path to a leaf node
        let path1 = Path::new(vec![Direction::Left, Direction::Left]);
        assert_eq!(tree.lca(&path1), Some((&1, path1.clone())));

        // Case 2: Path partially exists (extended beyond existing nodes)
        let path2 = Path::new(vec![Direction::Left, Direction::Left, Direction::Left]);
        assert_eq!(tree.lca(&path2), Some((&1, Path::new(vec![Direction::Left, Direction::Left]))));

        // Case 3: Path to another leaf node
        let path3 = Path::new(vec![Direction::Right, Direction::Right]);
        assert_eq!(tree.lca(&path3), Some((&4, path3.clone())));

        // Case 4: Empty path should return the root
        let path4 = Path::new(vec![]);
        assert_eq!(tree.lca(&path4), Some((&7, path4.clone())));

        // Case 5: Non-leaf node
        let path5 = Path::new(vec![Direction::Left]);
        assert_eq!(tree.lca(&path5), Some((&5, path5.clone())));

        // Case 6: Path that does not exist at all
        let path6 = Path::new(vec![Direction::Left, Direction::Right, Direction::Left]);
        assert_eq!(tree.lca(&path6), Some((&2, Path::new(vec![Direction::Left, Direction::Right]))));

        // Case 7: Path to a non-existent right child
        let path7 = Path::new(vec![Direction::Right, Direction::Left, Direction::Left]);
        assert_eq!(tree.lca(&path7), Some((&3, Path::new(vec![Direction::Right, Direction::Left]))));
    }

    #[test]
    fn test_write_method() {
        // Initialize a new BinaryTree with an initial root value
        let mut tree = BinaryTree::new(0);

        // Define paths for insertion
        let path_left_left = Path::new(vec![Direction::Left, Direction::Left]);
        let path_left_right = Path::new(vec![Direction::Left, Direction::Right]);
        let path_right_left = Path::new(vec![Direction::Right, Direction::Left]);
        let path_right_right = Path::new(vec![Direction::Right, Direction::Right]);

        // Write values to the tree at specified paths
        tree.write(1, path_left_left.clone());
        tree.write(2, path_left_right.clone());
        tree.write(3, path_right_left.clone());
        tree.write(4, path_right_right.clone());

        // Assert that the values are correctly written and retrievable
        assert_eq!(
            tree.get(&path_left_left),
            Some(&1),
            "Value at Left->Left should be 1"
        );
        assert_eq!(
            tree.get(&path_left_right),
            Some(&2),
            "Value at Left->Right should be 2"
        );
        assert_eq!(
            tree.get(&path_right_left),
            Some(&3),
            "Value at Right->Left should be 3"
        );
        assert_eq!(
            tree.get(&path_right_right),
            Some(&4),
            "Value at Right->Right should be 4"
        );

        // Additionally, ensure that the root value remains unchanged
        assert_eq!(
            tree.get(&Path::new(vec![])),
            Some(&0),
            "Root value should remain 0"
        );

        // Test overwriting an existing value
        tree.write(5, path_left_left.clone());
        assert_eq!(
            tree.get(&path_left_left),
            Some(&5),
            "Value at Left->Left should be updated to 5"
        );

        // Test writing to a deeper path
        let path_left_left_left = Path::new(vec![Direction::Left, Direction::Left, Direction::Left]);
        tree.write(6, path_left_left_left.clone());
        assert_eq!(
            tree.get(&path_left_left_left),
            Some(&6),
            "Value at Left->Left->Left should be 6"
        );

        // Test writing to a new branch
        let path_right_right_right = Path::new(vec![Direction::Right, Direction::Right, Direction::Right]);
        tree.write(7, path_right_right_right.clone());
        assert_eq!(
            tree.get(&path_right_right_right),
            Some(&7),
            "Value at Right->Right->Right should be 7"
        );

        // Ensure other paths remain unaffected
        assert_eq!(
            tree.get(&Path::new(vec![Direction::Left])),
            None,
            "Intermediate path Left should have no value"
        );
        assert_eq!(
            tree.get(&Path::new(vec![Direction::Right])),
            None,
            "Intermediate path Right should have no value"
        );
    }
}