use crate::Path;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Direction {
    Left,
    Right,
}

impl Into<u8> for Direction {
    fn into(self) -> u8 {
        match self {
            Direction::Left => 0,
            Direction::Right => 1,
        }
    }
}

impl From<u8> for Direction {
    fn from(value: u8) -> Self {
        match value {
            0 => Direction::Left,
            1 => Direction::Right,
            _ => panic!("Invalid direction value"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BinaryTree<T> {
    value: T,
    left: Option<Box<BinaryTree<T>>>,
    right: Option<Box<BinaryTree<T>>>,
}

impl<T> BinaryTree<T> {
    pub(crate) fn new(value: T) -> Self {
        BinaryTree { value, left: None, right: None }
    }
    pub fn from_vec_with_paths(items: Vec<(T, Path)>) -> Self
    where
        T: Clone + Default,
    {
        if items.is_empty() {
            return BinaryTree::new(T::default());
        }

        let mut root = BinaryTree::new(items[0].0.clone());

        for (value, path) in items {
            let mut current = &mut root;

            for &direction in &path {
                match direction {
                    Direction::Left => {
                        if current.left.is_none() {
                            current.left = Some(Box::new(BinaryTree::new(T::default())));
                        }
                        current = current.left.as_mut().unwrap();
                    }
                    Direction::Right => {
                        if current.right.is_none() {
                            current.right = Some(Box::new(BinaryTree::new(T::default())));
                        }
                        current = current.right.as_mut().unwrap();
                    }
                }
            }

            current.value = value;
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

    pub fn get(&self, index: usize) -> Option<&T> {
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

        Some(&current.value)
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
        assert_eq!(tree.value, 1);
        assert!(tree.left.is_none());
        assert!(tree.right.is_none());

        // Test from_vec_with_paths for a small tree
        let small_items = vec![
            (1, vec![Direction::Left, Direction::Left]),
            (2, vec![Direction::Left, Direction::Right]),
            (3, vec![Direction::Right, Direction::Left]),
            (4, vec![Direction::Right, Direction::Right]),
        ];
        let small_tree = BinaryTree::from_vec_with_paths(small_items);
        println!("Small tree:\n{}", small_tree);

        // Test get method for small tree
        assert_eq!(small_tree.get(0), Some(&1));
        assert_eq!(small_tree.get(1), Some(&2));
        assert_eq!(small_tree.get(2), Some(&3));
        assert_eq!(small_tree.get(3), Some(&4));
        assert_eq!(small_tree.get(4), None);
    }

    #[test]
    fn test_large_binary_tree() {
        // Test from_vec_with_paths for a larger tree with height 4 and some null values
        let large_items = vec![
            (1, vec![Direction::Left, Direction::Left, Direction::Left, Direction::Left]),
            (2, vec![Direction::Left, Direction::Left, Direction::Right, Direction::Right]),
            (3, vec![Direction::Left, Direction::Right, Direction::Left, Direction::Left]),
            (4, vec![Direction::Right, Direction::Left, Direction::Left, Direction::Left]),
            (5, vec![Direction::Right, Direction::Left, Direction::Right, Direction::Right]),
            (6, vec![Direction::Right, Direction::Right, Direction::Left, Direction::Left]),
            (7, vec![Direction::Right, Direction::Right, Direction::Right, Direction::Left]),
            (8, vec![Direction::Right, Direction::Right, Direction::Right, Direction::Right]),
        ];
        let large_tree = BinaryTree::from_vec_with_paths(large_items);
        println!("Large tree:\n{}", large_tree);

        // Test get method for large tree
        assert_eq!(large_tree.get(0), Some(&1));
        assert_eq!(large_tree.get(3), Some(&2));
        assert_eq!(large_tree.get(4), Some(&3));
        assert_eq!(large_tree.get(8), Some(&4));
        assert_eq!(large_tree.get(11), Some(&5));
        assert_eq!(large_tree.get(12), Some(&6));
        assert_eq!(large_tree.get(14), Some(&7));
        assert_eq!(large_tree.get(15), Some(&8));

        // Test null values
        assert_eq!(large_tree.get(1), None);
        assert_eq!(large_tree.get(2), None);
        assert_eq!(large_tree.get(5), None);
        assert_eq!(large_tree.get(6), None);
        assert_eq!(large_tree.get(7), None);
        assert_eq!(large_tree.get(9), None);
        assert_eq!(large_tree.get(10), None);
        assert_eq!(large_tree.get(13), None);
    }
}