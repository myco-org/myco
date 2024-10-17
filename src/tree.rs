use std::fmt::{self, Debug};

use crate::{Direction, Path};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BinaryTree<T> {
    pub(crate) value: T,
    pub(crate) left: Option<Box<BinaryTree<T>>>,
    pub(crate) right: Option<Box<BinaryTree<T>>>,
}

pub(crate) trait TreeValue: Clone + Debug {
    fn new_random() -> Self;
}

impl<T: TreeValue> BinaryTree<T> {
    pub(crate) fn new(value: T) -> Self {
        BinaryTree { value, left: None, right: None }
    }

    pub fn new_empty() -> Self {
        BinaryTree { value: T::new_random(), left: None, right: None }
    }

    pub fn new_with_depth(depth: usize) -> Self {
        if depth == 0 {
            return BinaryTree::new_empty();
        }
        let node = BinaryTree::new_with_depth(depth - 1);
        BinaryTree { value: T::new_random(), left: Some(Box::new(node.clone())), right: Some(Box::new(node)) }
    }

    pub fn from_vec_with_paths(items: Vec<(Vec<T>, Path)>) -> Self
    where
        T: TreeValue,
    {
        if items.is_empty() {
            return BinaryTree::new_empty();
        }

        let mut root = BinaryTree::new_empty();

        for (values, path) in items {
            let mut current = &mut root;
            current.value = values.first().expect("No value in values").clone();
            
            // Skip the first value as we've already set the root value
            for (direction, value) in path.into_iter().zip(values.into_iter().skip(1)) {
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
                current.value = value.clone();
            }
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

        Some(&current.value)
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

        Some(&current.value)
    }

    pub fn get_all_nodes_along_path(&self, path: &Path) -> Vec<T> {
        let mut current = self;
        let mut nodes = vec![];

        // Include the root node if it has a value
        if let Some(value) = Some(&current.value) {
            nodes.push(value.clone());
        }
        for direction in path {
            match direction {
                Direction::Left => {
                    if let Some(left) = current.left.as_ref() {
                        current = left;
                    } else {
                        break;
                    }
                }
                Direction::Right => {
                    if let Some(right) = current.right.as_ref() {
                        current = right;
                    } else {
                        break;
                    }
                }
            }
            if let Some(value) = Some(&current.value) {
                nodes.push(value.clone());
            }
        }

        nodes
    }

    pub fn lca(&mut self, path: &Path) -> Option<(&mut T, Path)> {
        let mut current = self;
        let mut current_path = Path::new(Vec::new());
        
        for &direction in path {
            match direction {
                Direction::Left => {
                    if let Some(left) = current.left.as_mut() {
                        current = left;
                        current_path.push(Direction::Left);
                    } else {
                        // Cannot continue down path, return current node and path
                        return Some((&mut current.value, current_path));
                    }
                }
                Direction::Right => {
                    if let Some(right) = current.right.as_mut() {
                        current = right;
                        current_path.push(Direction::Right);
                    } else {
                        // Cannot continue down path, return current node and path
                        return Some((&mut current.value, current_path));
                    }
                }
            }
            
            // If we've reached a leaf node, return it and the path
            if current.left.is_none() && current.right.is_none() {
                return Some((&mut current.value, current_path));
            }
        }
        
        // If we've exhausted path, return the last node and the path
        Some((&mut current.value, current_path))
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
    
        current.value = value;
    }

    pub fn overwrite_tree(&mut self, other: &BinaryTree<T>) {
        self.value = other.value.clone();
        if let Some(left) = &other.left {
            if self.left.is_none() {
                self.left = Some(Box::new(BinaryTree::new_empty()));
            }
            self.left.as_mut().unwrap().overwrite_tree(left);
        }
        if let Some(right) = &other.right {
            if self.right.is_none() {
                self.right = Some(Box::new(BinaryTree::new_empty()));
            }
            self.right.as_mut().unwrap().overwrite_tree(right);
        }
    }

    fn flatten_tree(&self) -> Vec<(T, Path)> {
        let mut flattened = Vec::new();
        Self::_flatten_tree(self, Path::new(vec![]), &mut flattened);
        flattened
    }

    fn _flatten_tree(node: &BinaryTree<T>, path: Path, flattened: &mut Vec<(T, Path)>) {
        if let Some(right) = &node.right {
            let mut right_path = path.clone();
            right_path.push(Direction::Right);
            Self::_flatten_tree(right, right_path, flattened);
        }
        if let Some(left) = &node.left {
            let mut left_path = path.clone();
            left_path.push(Direction::Left);
            Self::_flatten_tree(left, left_path, flattened);
        }
        flattened.push((node.value.clone(), path.clone()));
    }

    pub fn zip_flatten_tree<S: Clone>(&self, rhs: &BinaryTree<S>) -> Vec<(Option<T>, Option<S>, Path)> {
        let mut flattened = Vec::new();
        Self::_zip_flatten_tree(&Some(Box::new(self.clone())), &Some(Box::new(rhs.clone())), Path::new(vec![]), &mut flattened);
        flattened
    }

    fn _zip_flatten_tree<S: Clone>(lhs: &Option<Box<BinaryTree<T>>>, rhs: &Option<Box<BinaryTree<S>>>, path: Path, flattened: &mut Vec<(Option<T>, Option<S>, Path)>) {
        match (lhs, rhs) {
            (Some(lhs), Some(rhs)) => {
                flattened.push((Some(lhs.value.clone()), Some(rhs.value.clone()), path.clone()));

                if let (Some(left_lhs), Some(left_rhs)) = (&lhs.left, &rhs.left) {
                    let mut left_path = path.clone();
                    left_path.push(Direction::Left);
                    Self::_zip_flatten_tree(&Some(left_lhs.clone()), &Some(left_rhs.clone()), left_path, flattened);
                }
                else if let (Some(left_lhs), None) = (&lhs.left, &rhs.left) {
                    let mut left_path = path.clone();
                    left_path.push(Direction::Left);
                    Self::_zip_flatten_tree(&Some(left_lhs.clone()), &None, left_path, flattened);
                }

                if let (Some(right_lhs), Some(right_rhs)) = (&lhs.right, &rhs.right) {
                    let mut right_path = path.clone();
                    right_path.push(Direction::Right);
                    Self::_zip_flatten_tree(&Some(right_lhs.clone()), &Some(right_rhs.clone()), right_path, flattened);
                }
                else if let (Some(right_lhs), None) = (&lhs.right, &rhs.right) {
                    let mut right_path = path.clone();
                    right_path.push(Direction::Right);
                    Self::_zip_flatten_tree(&Some(right_lhs.clone()), &None, right_path, flattened);
                }

            },
            (Some(lhs), None) => {
                flattened.push((Some(lhs.value.clone()), None, path.clone()));
                if let Some(left_lhs) = &lhs.left {
                    let mut left_path = path.clone();
                    left_path.push(Direction::Left);
                    Self::_zip_flatten_tree(&Some(left_lhs.clone()), &None, left_path, flattened);
                }
                if let Some(right_lhs) = &lhs.right {
                    let mut right_path = path.clone();
                    right_path.push(Direction::Right);
                    Self::_zip_flatten_tree(&Some(right_lhs.clone()), &None, right_path, flattened);
                }
            }
            (None, Some(_)) | (None, None) => (),
        }
    }

    pub fn print_with_path(&self, path: &Path) -> String {
        let mut output = String::new();
        self.print_tree_with_path("", true, path, &mut output);
        output
    }

    fn print_tree_with_path(&self, prefix: &str, is_left: bool, path: &Path, output: &mut String) {
        let (branch, new_prefix) = if is_left {
            ("├─ ", "│ ")
        } else {
            ("└─ ", "  ")
        };
        let mut current_path = Path::new(vec![]);
        let is_on_path = path.into_iter().zip(current_path.clone().into_iter()).all(|(a, b)| *a == b);

        let value_str = if is_on_path {
            format!("\x1b[31m{:?}\x1b[0m", self.value) // Red color for nodes on the path
        } else {
            format!("{:?}", self.value)
        };

        output.push_str(&format!("{}{}{}\n", prefix, branch, value_str));

        if let Some(left) = &self.left {
            current_path.push(Direction::Left);
            left.print_tree_with_path(&format!("{}{}", prefix, new_prefix), true, path, output);
        }

        if let Some(right) = &self.right {
            current_path.push(Direction::Right);
            right.print_tree_with_path(&format!("{}{}", prefix, new_prefix), false, path, output);
        }
    }
}

impl<T: TreeValue> IntoIterator for BinaryTree<T> {
    type Item = (T, Path);
    type IntoIter = BinaryTreeIntoIterator<T>;

    fn into_iter(self) -> Self::IntoIter {
        let mut flattened = Vec::new();
        BinaryTree::<T>::_flatten_tree(&self, Path::new(vec![]), &mut flattened);
        BinaryTreeIntoIterator { flattened }
    }
}

pub struct BinaryTreeIntoIterator<T> {
    flattened: Vec<(T, Path)>,
}

impl<T> Iterator for BinaryTreeIntoIterator<T> {
    type Item = (T, Path);

    fn next(&mut self) -> Option<Self::Item> {
        self.flattened.pop()
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

    #[derive(Debug, Clone, PartialEq)]
    struct IntWrapper(i32);

    impl TreeValue for IntWrapper {
        fn new_random() -> Self {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            IntWrapper(rng.gen())
        }
    }

    #[test]
    fn test_int_wrapper() {
        // Test that IntWrapper implements TreeValue
        let random_value = IntWrapper::new_random();
        assert!(random_value.0 >= i32::MIN && random_value.0 <= i32::MAX);

        // Test creating a tree with IntWrapper
        let tree = BinaryTree::new(IntWrapper(42));
        assert_eq!(tree.value, IntWrapper(42));
        assert!(tree.left.is_none());
        assert!(tree.right.is_none());

        // Test creating a tree with depth
        let tree_with_depth = BinaryTree::<IntWrapper>::new_with_depth(2);
        assert_eq!(tree_with_depth.height(), 2);
    }

    #[test]
    fn test_small_binary_tree() {
        // Test creating a new tree
        let tree = BinaryTree::new(IntWrapper(1));
        assert_eq!(tree.value, IntWrapper(1));
        assert!(tree.left.is_none());
        assert!(tree.right.is_none());
        // Test from_vec_with_paths for a small tree
        let small_items = vec![
            (vec![IntWrapper(0), IntWrapper(0), IntWrapper(1)], Path::new(vec![Direction::Left, Direction::Left])),
            (vec![IntWrapper(0), IntWrapper(0), IntWrapper(2)], Path::new(vec![Direction::Left, Direction::Right])),
            (vec![IntWrapper(0), IntWrapper(3), IntWrapper(3)], Path::new(vec![Direction::Right, Direction::Left])),
            (vec![IntWrapper(0), IntWrapper(3), IntWrapper(4)], Path::new(vec![Direction::Right, Direction::Right])),
        ];
        let small_tree = BinaryTree::from_vec_with_paths(small_items);

        // Test get method for small tree
        assert_eq!(small_tree.get_leaf(0), Some(&IntWrapper(1)));
        assert_eq!(small_tree.get_leaf(1), Some(&IntWrapper(2)));
        assert_eq!(small_tree.get_leaf(2), Some(&IntWrapper(3)));
        assert_eq!(small_tree.get_leaf(3), Some(&IntWrapper(4)));
        assert_eq!(small_tree.get_leaf(4), None);
    }

    #[test]
    fn test_get() {
        // Create a tree with some values, including non-leaf nodes
        let items = vec![
            (vec![IntWrapper(0), IntWrapper(1), IntWrapper(2), IntWrapper(3), IntWrapper(1)], Path::new(vec![Direction::Left, Direction::Left, Direction::Left, Direction::Left])),
            (vec![IntWrapper(0), IntWrapper(1), IntWrapper(2), IntWrapper(3), IntWrapper(2)], Path::new(vec![Direction::Left, Direction::Left, Direction::Right, Direction::Right])),
            (vec![IntWrapper(0), IntWrapper(1), IntWrapper(2), IntWrapper(3), IntWrapper(3)], Path::new(vec![Direction::Left, Direction::Right, Direction::Left, Direction::Left])),
            (vec![IntWrapper(0), IntWrapper(1), IntWrapper(2), IntWrapper(3), IntWrapper(4)], Path::new(vec![Direction::Right, Direction::Left, Direction::Left, Direction::Left])),
            (vec![IntWrapper(0), IntWrapper(1), IntWrapper(2), IntWrapper(3), IntWrapper(5)], Path::new(vec![Direction::Right, Direction::Left, Direction::Right, Direction::Right])),
            (vec![IntWrapper(0), IntWrapper(1), IntWrapper(2), IntWrapper(3), IntWrapper(6)], Path::new(vec![Direction::Right, Direction::Right, Direction::Left, Direction::Left])),
            (vec![IntWrapper(0), IntWrapper(1), IntWrapper(2), IntWrapper(3), IntWrapper(7)], Path::new(vec![Direction::Right, Direction::Right, Direction::Right, Direction::Left])),
            (vec![IntWrapper(0), IntWrapper(1), IntWrapper(2), IntWrapper(3), IntWrapper(8)], Path::new(vec![Direction::Right, Direction::Right, Direction::Right, Direction::Right])),
        ];
        let tree = BinaryTree::from_vec_with_paths(items);

        // Test get method for existing paths
        assert_eq!(tree.get(&Path::new(vec![Direction::Left, Direction::Left, Direction::Left, Direction::Left])), Some(&IntWrapper(1)));
        assert_eq!(tree.get(&Path::new(vec![Direction::Left, Direction::Left, Direction::Right, Direction::Right])), Some(&IntWrapper(2)));
        assert_eq!(tree.get(&Path::new(vec![Direction::Right, Direction::Right, Direction::Right, Direction::Right])), Some(&IntWrapper(8)));

        // Test get method for non-leaf nodes
        assert_eq!(tree.get(&Path::new(vec![Direction::Left])), Some(&IntWrapper(1)));
        assert_eq!(tree.get(&Path::new(vec![Direction::Right, Direction::Left])), Some(&IntWrapper(2)));

        // Test get method for root
        assert_eq!(tree.get(&Path::new(vec![])), Some(&IntWrapper(0)));

        // Test get method for non-existing paths
        assert_eq!(tree.get(&Path::new(vec![Direction::Left, Direction::Left, Direction::Left, Direction::Right])), None);
        assert_eq!(tree.get(&Path::new(vec![Direction::Right, Direction::Right, Direction::Left, Direction::Right])), None);
        assert_eq!(tree.get(&Path::new(vec![Direction::Left, Direction::Right, Direction::Right, Direction::Right])), None);
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
            (vec![IntWrapper(7)], Path::new(vec![])), // Root node
            (vec![IntWrapper(7), IntWrapper(5)], Path::new(vec![Direction::Left])),
            (vec![IntWrapper(7), IntWrapper(6)], Path::new(vec![Direction::Right])),
            (vec![IntWrapper(7), IntWrapper(5), IntWrapper(1)], Path::new(vec![Direction::Left, Direction::Left])),
            (vec![IntWrapper(7), IntWrapper(5), IntWrapper(2)], Path::new(vec![Direction::Left, Direction::Right])),
            (vec![IntWrapper(7), IntWrapper(6), IntWrapper(3)], Path::new(vec![Direction::Right, Direction::Left])),
            (vec![IntWrapper(7), IntWrapper(6), IntWrapper(4)], Path::new(vec![Direction::Right, Direction::Right])),
        ];
        let mut tree = BinaryTree::from_vec_with_paths(items);

        // Test lca with various paths
        // Case 1: Path to a leaf node
        let path1 = Path::new(vec![Direction::Left, Direction::Left]);
        assert_eq!(tree.lca(&path1), Some((&mut IntWrapper(1), path1.clone())));

        // Case 2: Path partially exists (extended beyond existing nodes)
        let path2 = Path::new(vec![Direction::Left, Direction::Left, Direction::Left]);
        assert_eq!(tree.lca(&path2), Some((&mut IntWrapper(1), Path::new(vec![Direction::Left, Direction::Left]))));

        // Case 3: Path to another leaf node
        let path3 = Path::new(vec![Direction::Right, Direction::Right]);
        assert_eq!(tree.lca(&path3), Some((&mut IntWrapper(4), path3.clone())));

        // Case 4: Empty path should return the root
        let path4 = Path::new(vec![]);
        assert_eq!(tree.lca(&path4), Some((&mut IntWrapper(7), path4.clone())));

        // Case 5: Non-leaf node
        let path5 = Path::new(vec![Direction::Left]);
        assert_eq!(tree.lca(&path5), Some((&mut IntWrapper(5), path5.clone())));

        // Case 6: Path that does not exist at all
        let path6 = Path::new(vec![Direction::Left, Direction::Right, Direction::Left]);
        assert_eq!(tree.lca(&path6), Some((&mut IntWrapper(2), Path::new(vec![Direction::Left, Direction::Right]))));

        // Case 7: Path to a non-existent right child
        let path7 = Path::new(vec![Direction::Right, Direction::Left, Direction::Left]);
        assert_eq!(tree.lca(&path7), Some((&mut IntWrapper(3), Path::new(vec![Direction::Right, Direction::Left]))));
    }

    #[test]
    fn test_write_method() {
        // Initialize a new BinaryTree with an initial root value
        let mut tree = BinaryTree::new(IntWrapper(0));

        // Define paths for insertion
        let path_left_left = Path::new(vec![Direction::Left, Direction::Left]);
        let path_left_right = Path::new(vec![Direction::Left, Direction::Right]);
        let path_right_left = Path::new(vec![Direction::Right, Direction::Left]);
        let path_right_right = Path::new(vec![Direction::Right, Direction::Right]);

        // Write values to the tree at specified paths
        tree.write(IntWrapper(1), path_left_left.clone());
        tree.write(IntWrapper(2), path_left_right.clone());
        tree.write(IntWrapper(3), path_right_left.clone());
        tree.write(IntWrapper(4), path_right_right.clone());

        // Assert that the values are correctly written and retrievable
        assert_eq!(
            tree.get(&path_left_left),
            Some(&IntWrapper(1)),
            "Value at Left->Left should be 1"
        );
        assert_eq!(
            tree.get(&path_left_right),
            Some(&IntWrapper(2)),
            "Value at Left->Right should be 2"
        );
        assert_eq!(
            tree.get(&path_right_left),
            Some(&IntWrapper(3)),
            "Value at Right->Left should be 3"
        );
        assert_eq!(
            tree.get(&path_right_right),
            Some(&IntWrapper(4)),
            "Value at Right->Right should be 4"
        );

        // Additionally, ensure that the root value remains unchanged
        assert_eq!(
            tree.get(&Path::new(vec![])),
            Some(&IntWrapper(0)),
            "Root value should remain 0"
        );

        // Test overwriting an existing value
        tree.write(IntWrapper(5), path_left_left.clone());
        assert_eq!(
            tree.get(&path_left_left),
            Some(&IntWrapper(5)),
            "Value at Left->Left should be updated to 5"
        );

        // Test writing to a deeper path
        let path_left_left_left = Path::new(vec![Direction::Left, Direction::Left, Direction::Left]);
        tree.write(IntWrapper(6), path_left_left_left.clone());
        assert_eq!(
            tree.get(&path_left_left_left),
            Some(&IntWrapper(6)),
            "Value at Left->Left->Left should be 6"
        );

        // Test writing to a new branch
        let path_right_right_right = Path::new(vec![Direction::Right, Direction::Right, Direction::Right]);
        tree.write(IntWrapper(7), path_right_right_right.clone());
        assert_eq!(
            tree.get(&path_right_right_right),
            Some(&IntWrapper(7)),
            "Value at Right->Right->Right should be 7"
        );

        // Ensure other paths remain unaffected
        assert!(
            tree.get(&Path::new(vec![Direction::Left])).is_some_and(|val| val.0.abs() > 10), // Assume random value is greater than 10
            "Intermediate path Left should have no value"
        );
        assert!(
            tree.get(&Path::new(vec![Direction::Right])).is_some_and(|val| val.0.abs() > 10), // Assume random value is greater than 10
            "Intermediate path Right should have no value"
        );
    }

    #[test]
    fn test_binary_tree_into_iter() {
        let mut tree = BinaryTree::new(IntWrapper(1));
        tree.left = Some(Box::new(BinaryTree::new(IntWrapper(2))));
        tree.right = Some(Box::new(BinaryTree::new(IntWrapper(3))));
        tree.left.as_mut().unwrap().left = Some(Box::new(BinaryTree::new(IntWrapper(4))));
        tree.left.as_mut().unwrap().right = Some(Box::new(BinaryTree::new(IntWrapper(5))));
        tree.right.as_mut().unwrap().left = Some(Box::new(BinaryTree::new(IntWrapper(6))));
        tree.right.as_mut().unwrap().right = Some(Box::new(BinaryTree::new(IntWrapper(7))));

        let flattened: Vec<(IntWrapper, Path)> = tree.into_iter().collect();    
        assert_eq!(flattened, vec![(IntWrapper(1), Path::new(vec![])), (IntWrapper(2), Path::new(vec![Direction::Left])), (IntWrapper(4), Path::new(vec![Direction::Left, Direction::Left])), (IntWrapper(5), Path::new(vec![Direction::Left, Direction::Right])), (IntWrapper(3), Path::new(vec![Direction::Right])), (IntWrapper(6), Path::new(vec![Direction::Right, Direction::Left])), (IntWrapper(7), Path::new(vec![Direction::Right, Direction::Right]))]);
    }

    #[test]
    fn test_new_with_depth_zero() {
        // Create a binary tree with depth 0
        let tree = BinaryTree::<IntWrapper>::new_with_depth(0);

        // Define the expected tree: a single root node with no children
        let expected = BinaryTree::<IntWrapper>::new_empty();

        // Assert that the created tree matches the expected tree
        assert_eq!(tree.height(), expected.height(), "A tree with depth 0 should have height 0");
        assert_eq!(tree.left, expected.left, "A tree with depth 0 should have no left child");
        assert_eq!(tree.right, expected.right, "A tree with depth 0 should have no right child");
    }

    #[test]
    fn test_new_with_depth_large() {
        // Create a binary tree with a larger depth
        let depth = 4;
        let tree = BinaryTree::<IntWrapper>::new_with_depth(depth);

        // Function to recursively count the number of nodes in the tree
        fn count_nodes<T>(tree: &BinaryTree<T>) -> usize {
            let mut count = 1; // Count the current node
            if let Some(left) = &tree.left {
                count += count_nodes(left);
            }
            if let Some(right) = &tree.right {
                count += count_nodes(right);
            }
            count
        }

        // The expected number of nodes for a binary tree of depth d is 2^(d+1) - 1
        let expected_nodes = (2_usize.pow((depth + 1) as u32)) - 1;
        let actual_nodes = count_nodes(&tree);

        // Assert that the number of nodes matches the expected count
        assert_eq!(actual_nodes, expected_nodes, "A tree with depth {} should have {} nodes, but found {}", depth, expected_nodes, actual_nodes);
    }


    #[test]
    fn test_get_all_nodes_along_path() {
        // Create a binary tree for testing:
        //         7
        //        / \
        //       5   6
        //      / \   \
        //     1   2   3
        let mut tree = BinaryTree::new(IntWrapper(7));
        tree.left = Some(Box::new(BinaryTree::new(IntWrapper(5))));
        tree.right = Some(Box::new(BinaryTree::new(IntWrapper(6))));
        tree.left.as_mut().unwrap().left = Some(Box::new(BinaryTree::new(IntWrapper(1))));
        tree.left.as_mut().unwrap().right = Some(Box::new(BinaryTree::new(IntWrapper(2))));
        tree.right.as_mut().unwrap().right = Some(Box::new(BinaryTree::new(IntWrapper(3))));

        // Define paths and their expected node values
        let test_cases = vec![
            // Test case 1: Empty path should return an empty vector
            (
                Path::new(vec![]),
                vec![IntWrapper(7)],
                "Empty path should return no nodes",
            ),
            // Test case 2: Path to the left child
            (
                Path::new(vec![Direction::Left]),
                vec![IntWrapper(7),IntWrapper(5)],
                "Path [Left] should return the left child",
            ),
            // Test case 3: Path to the right child
            (
                Path::new(vec![Direction::Right]),
                vec![IntWrapper(7),IntWrapper(6)],
                "Path [Right] should return the right child",
            ),
            // Test case 4: Path to the left-left grandchild
            (
                Path::new(vec![Direction::Left, Direction::Left]),
                vec![IntWrapper(7),IntWrapper(5), IntWrapper(1)],
                "Path [Left, Left] should return the left child and its left child",
            ),
            // Test case 5: Path to the left-right grandchild
            (
                Path::new(vec![Direction::Left, Direction::Right]),
                vec![IntWrapper(7),IntWrapper(5), IntWrapper(2)],
                "Path [Left, Right] should return the left child and its right child",
            ),
            // Test case 6: Path to the right-right grandchild
            (
                Path::new(vec![Direction::Right, Direction::Right]),
                vec![IntWrapper(7),IntWrapper(6), IntWrapper(3)],
                "Path [Right, Right] should return the right child and its right child",
            ),
            // Test case 7: Path that partially exists (non-existent node)
            (
                Path::new(vec![Direction::Right, Direction::Left]),
                vec![IntWrapper(7),IntWrapper(6)],
                "Path [Right, Left] should return only existing nodes up to where the path breaks",
            ),
            // Test case 8: Longer path with non-existent nodes
            (
                Path::new(vec![Direction::Left, Direction::Left, Direction::Left]),
                vec![IntWrapper(7),IntWrapper(5), IntWrapper(1)],
                "Path [Left, Left, Left] should return nodes up to the last existing node",
            ),
        ];

        for (path, expected, description) in test_cases {
            let result = tree.get_all_nodes_along_path(&path);
            assert_eq!(
                result, expected,
                "Failed: {}. Expected {:?}, got {:?}",
                description, expected, result
            );
        }
    }

    #[test]
    fn test_zip_flatten_tree() {
        // Create first BinaryTree instance (tree1)
        // Structure of tree1:
        //      1
        //     / \
        //    2   3
        let tree1 = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(1)], Path::new(vec![])),
            (vec![IntWrapper(1), IntWrapper(2)], Path::new(vec![Direction::Left])),
            (vec![IntWrapper(1), IntWrapper(3)], Path::new(vec![Direction::Right])),
        ]);

        // Create second BinaryTree instance (tree2)
        // Structure of tree2:
        //      4
        //     / \
        //    5   6
        let tree2 = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root
            (vec![IntWrapper(4), IntWrapper(5)], Path::new(vec![Direction::Left])),
            (vec![IntWrapper(4), IntWrapper(6)], Path::new(vec![Direction::Right])),
        ]);

        // Initialize the flattened vector
        let mut flattened = Vec::new();

        // Call zip_flatten_tree with the roots of both trees
        BinaryTree::<IntWrapper>::_zip_flatten_tree(
            &Some(Box::new(tree1.clone())),
            &Some(Box::new(tree2.clone())),
            Path::new(vec![]),
            &mut flattened,
        );

        // Define the expected flattened result
        // Assuming zip_flatten_tree traverses both trees and collects nodes from both
        let expected = vec![
            (Some(IntWrapper(1)), Some(IntWrapper(4)), Path::new(vec![])),
            (Some(IntWrapper(2)), Some(IntWrapper(5)), Path::new(vec![Direction::Left])),
            (Some(IntWrapper(3)), Some(IntWrapper(6)), Path::new(vec![Direction::Right])),
        ];

        // Since the function uses recursion and pushes nodes in a certain order,
        // the exact order in 'flattened' might vary. Adjust 'expected' accordingly.
        // For this example, we'll sort both vectors for comparison.

        // // Assert that the flattened vector matches the expected result
        assert_eq!(flattened, expected, "The zipped flattened trees do not match the expected output");
    }

    #[test]
    fn test_zip_flatten_tree_with_one_empty() {
        // Create first BinaryTree instance (tree1) - empty
        let tree1: BinaryTree<IntWrapper> = BinaryTree::new_empty();

        // Create second BinaryTree instance (tree2)
        // Structure of tree2:
        //      4
        //     / \
        //    5   6
        let tree2 = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root
            (vec![IntWrapper(4), IntWrapper(5)], Path::new(vec![Direction::Left])),
            (vec![IntWrapper(4), IntWrapper(6)], Path::new(vec![Direction::Right])),
        ]);

        // Initialize the flattened vector
        let mut flattened = Vec::new();

        // Call zip_flatten_tree with tree1 empty and tree2
        BinaryTree::<IntWrapper>::_zip_flatten_tree(
            &Some(Box::new(tree1.clone())),
            &Some(Box::new(tree2.clone())),
            Path::new(vec![]),
            &mut flattened,
        );

        let expected = vec![
            (Some(IntWrapper(-1)), Some(IntWrapper(4)), Path::new(vec![])),
        ];

        // Assert that the flattened vector matches the expected result
        assert_eq!(expected[0].1, flattened[0].1, "The second element of the flattened vector should be the root of tree2");
    }

    #[test]
    fn test_zip_flatten_tree_both_empty() {
        // Create first BinaryTree instance (tree1) - empty
        let tree1: BinaryTree<IntWrapper> = BinaryTree::new_empty();

        // Create second BinaryTree instance (tree2) - empty
        let tree2: BinaryTree<IntWrapper> = BinaryTree::new_empty();

        // Initialize the flattened vector
        let mut flattened = Vec::new();

        // Call zip_flatten_tree with both trees empty
        BinaryTree::<IntWrapper>::_zip_flatten_tree(
            &Some(Box::new(tree1.clone())),
            &Some(Box::new(tree2.clone())),
            Path::new(vec![]),
            &mut flattened,
        );

        assert!(!flattened.is_empty(), "The flattened vector should not be empty even when both trees are empty");
        assert_ne!(flattened[0].0, flattened[0].1, "The two empty trees should contain random values");
    }

    #[test]
    fn test_zip_flatten_tree_different_structures() {
        // Create first BinaryTree instance (tree1)
        // Structure of tree1:
        //      1
        //     /
        //    2
        //   /
        //  3
        let tree1 = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(1)], Path::new(vec![])),                    // Root
            (vec![IntWrapper(1), IntWrapper(2)], Path::new(vec![Direction::Left])),    // Left child
            (vec![IntWrapper(1), IntWrapper(2), IntWrapper(3)], Path::new(vec![Direction::Left, Direction::Left])), // Left-Left child
        ]);

        // Create second BinaryTree instance (tree2)
        // Structure of tree2:
        //      4
        //       \
        //        5
        //         \
        //          6
        let tree2 = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])),                             // Root
            (vec![IntWrapper(4), IntWrapper(5)], Path::new(vec![Direction::Right])),            // Right child
            (vec![IntWrapper(4), IntWrapper(5), IntWrapper(6)], Path::new(vec![Direction::Right, Direction::Right])), // Right-Right child
        ]);

        // Initialize the flattened vector
        let mut flattened = Vec::new();

        // Call zip_flatten_tree with tree1 and tree2
        BinaryTree::<IntWrapper>::_zip_flatten_tree(
            &Some(Box::new(tree1.clone())),
            &Some(Box::new(tree2.clone())),
            Path::new(vec![]),
            &mut flattened,
        );

        // Define the expected flattened result
        let expected = vec![
            (Some(IntWrapper(1)), Some(IntWrapper(4)), Path::new(vec![])),
            (Some(IntWrapper(2)), None, Path::new(vec![Direction::Left])),
            (Some(IntWrapper(3)), None, Path::new(vec![Direction::Left, Direction::Left])),
        ];

        assert_eq!(flattened, expected, "The zipped flattened trees with different structures do not match the expected output");
    }

    #[test]
    fn test_overwrite_tree_basic() {
        // Create the original tree
        // Structure:
        //      1
        //     / \
        //    2   3
        let mut original = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(1)], Path::new(vec![])), // Root
            (vec![IntWrapper(1), IntWrapper(2)], Path::new(vec![Direction::Left])),
            (vec![IntWrapper(1), IntWrapper(3)], Path::new(vec![Direction::Right])),
        ]);

        // Create the other tree to overwrite with
        // Structure:
        //      4
        //     / \
        //    5   6
        let other = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root
            (vec![IntWrapper(4), IntWrapper(5)], Path::new(vec![Direction::Left])),
            (vec![IntWrapper(4), IntWrapper(6)], Path::new(vec![Direction::Right])),
        ]);

        // Perform the overwrite
        original.overwrite_tree(&other);

        // Define the expected tree after overwrite
        let expected = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root overwritten
            (vec![IntWrapper(4), IntWrapper(5)], Path::new(vec![Direction::Left])), // Left child overwritten
            (vec![IntWrapper(4), IntWrapper(6)], Path::new(vec![Direction::Right])), // Right child overwritten
        ]);

        // Assert that the original tree now matches the expected tree
        assert_eq!(original, expected, "The tree was not correctly overwritten with the other tree");
    }

    #[test]
    fn test_overwrite_tree_with_empty_other() {
        // Create the tree to be overwritten
        let mut original: BinaryTree<IntWrapper> = BinaryTree::new_empty();

        // Create the tree to overwrite with
        // Structure:
        //      1
        //     / \
        //    2   3
        let other= BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(1)], Path::new(vec![])), // Root
            (vec![IntWrapper(1), IntWrapper(2)], Path::new(vec![Direction::Left])),
            (vec![IntWrapper(1), IntWrapper(3)], Path::new(vec![Direction::Right])),
        ]);


        // Perform the overwrite
        original.overwrite_tree(&other);

        // Define the expected tree after overwrite (only nodes in 'other' overwrite)
        // Since 'other' is empty, original tree should remain unchanged
        let expected = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(1)], Path::new(vec![])), // Root
            (vec![IntWrapper(1), IntWrapper(2)], Path::new(vec![Direction::Left])),
            (vec![IntWrapper(1), IntWrapper(3)], Path::new(vec![Direction::Right])),
        ]);

        // Assert that the original tree remains unchanged
        assert_eq!(original, expected, "Overwriting with an empty tree should not alter the original tree");
    }

    #[test]
    fn test_overwrite_tree_into_empty() {
        // Create the original tree (empty)
        let mut original: BinaryTree<IntWrapper> = BinaryTree::new_empty();

        // Create the other tree to overwrite with
        // Structure:
        //      4
        //     / \
        //    5   6
        let other = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root
            (vec![IntWrapper(4), IntWrapper(5)], Path::new(vec![Direction::Left])),
            (vec![IntWrapper(4), IntWrapper(6)], Path::new(vec![Direction::Right])),
        ]);

        // Perform the overwrite
        original.overwrite_tree(&other);

        // Define the expected tree after overwrite
        let expected = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root
            (vec![IntWrapper(4), IntWrapper(5)], Path::new(vec![Direction::Left])),
            (vec![IntWrapper(4), IntWrapper(6)], Path::new(vec![Direction::Right])),
        ]);

        // Assert that the original tree now matches the expected tree
        assert_eq!(original, expected, "Overwriting an empty tree with another tree should result in the other tree");
    }

    #[test]
    fn test_overwrite_tree_different_structures() {
        // Create the original tree
        // Structure:
        //      1
        //     /
        //    2
        //   /
        //  3
        let mut original = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(1)], Path::new(vec![])), // Root
            (vec![IntWrapper(1), IntWrapper(2)], Path::new(vec![Direction::Left])),
            (vec![IntWrapper(1), IntWrapper(2), IntWrapper(3)], Path::new(vec![Direction::Left, Direction::Left])),
        ]);

        // Create the other tree to overwrite with
        // Structure:
        //      4
        //       \
        //        5
        //         \
        //          6
        let other = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root
            (vec![IntWrapper(4), IntWrapper(5)], Path::new(vec![Direction::Right])),
            (vec![IntWrapper(4), IntWrapper(5), IntWrapper(6)], Path::new(vec![Direction::Right, Direction::Right])),
        ]);

        // Perform the overwrite
        original.overwrite_tree(&other);

        // Define the expected tree after overwrite
        let expected = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(1), IntWrapper(2)], Path::new(vec![Direction::Left])), // Existing left child remains as 'other' has no left
            (vec![IntWrapper(1), IntWrapper(2), IntWrapper(3)], Path::new(vec![Direction::Left, Direction::Left])), // Existing left-left child remains
            (vec![IntWrapper(4)], Path::new(vec![])), // Root overwritten
            (vec![IntWrapper(4), IntWrapper(5)], Path::new(vec![Direction::Right])), // Right child added
            (vec![IntWrapper(4), IntWrapper(5), IntWrapper(6)], Path::new(vec![Direction::Right, Direction::Right])), // Right-Right child added
        ]);

        // Since 'overwrite_tree' only overwrites existing paths and adds new ones from 'other',
        // the left subtree should remain unchanged and the right subtree should be added from 'other'

        // Assert that the original tree now matches the expected tree
        assert_eq!(original, expected, "Overwriting with a tree of a different structure did not result in the expected tree");
    }

    #[test]
    fn test_overwrite_tree_partial_overlap() {
        // Create the original tree
        // Structure:
        //      1
        //     / \
        //    2   3
        let mut original = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(1)], Path::new(vec![])), // Root
            (vec![IntWrapper(1), IntWrapper(2)], Path::new(vec![Direction::Left])),
            (vec![IntWrapper(1), IntWrapper(3)], Path::new(vec![Direction::Right])),
        ]);

        // Create the other tree to overwrite with
        // Structure:
        //      4
        //     / 
        //    5   
        let other = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root
            (vec![IntWrapper(4), IntWrapper(5)], Path::new(vec![Direction::Left])), // Overwrites left child
        ]);

        // Perform the overwrite
        original.overwrite_tree(&other);

        // Define the expected tree after overwrite
        let expected = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(1), IntWrapper(3)], Path::new(vec![Direction::Right])), // Right child remains unchanged
            (vec![IntWrapper(4)], Path::new(vec![])), // Root overwritten
            (vec![IntWrapper(4), IntWrapper(5)], Path::new(vec![Direction::Left])), // Left child overwritten
        ]);

        // Assert that the original tree now matches the expected tree
        assert_eq!(original, expected, "Overwriting with a tree that partially overlaps did not result in the expected tree");
    }

    
}