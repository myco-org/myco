use std::fmt::{self, Display, Debug};
use crate::{Direction, Path, McOsamError};

pub trait BinaryTree<T: Clone> {
    fn new(value: T) -> Self;
    fn new_empty() -> Self;
    fn new_with_depth(depth: usize) -> Self;
    fn from_vec_with_paths(items: Vec<(Vec<T>, Path)>) -> Self where T: Clone + Default + Debug;
    fn height(&self) -> usize;
    fn get_leaf(&self, index: usize) -> Option<&T>;
    fn get(&self, path: &Path) -> Option<&T>;
    fn get_all_nodes_along_path(&self, path: &Path) -> Vec<T>;
    fn lca(&mut self, path: &Path) -> Option<(&mut T, Path)>;
    fn write(&mut self, value: T, path: Path);
    fn overwrite_tree(&mut self, other: &Self);
    fn flatten_tree(&self) -> Vec<(T, Path)>;
    fn zip<S: Clone>(&self, rhs: &impl BinaryTree<S>) -> Vec<(Option<T>, Option<S>, Path)> where Self: Sized;
}

// Implement IntoIterator for BalancedBinaryTree
impl<T: Clone + Display> IntoIterator for BalancedBinaryTree<T> {
    type Item = (T, Path);
    type IntoIter = BinaryTreeIntoIterator<T>;

    fn into_iter(self) -> Self::IntoIter {
        let mut flattened = Vec::new();
        self.flatten_tree().into_iter().for_each(|(value, path)| {
            flattened.push((value, path));
        });
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

#[derive(Debug, Clone, PartialEq)]
pub struct BalancedBinaryTree<T> {
    value: Option<T>,
    left: Option<Box<BalancedBinaryTree<T>>>,
    right: Option<Box<BalancedBinaryTree<T>>>,
}

impl<T: Clone> BinaryTree<T> for BalancedBinaryTree<T> {
    fn new(value: T) -> Self {
        BalancedBinaryTree { value: Some(value), left: None, right: None }
    }

    fn new_empty() -> Self {
        BalancedBinaryTree { value: None, left: None, right: None }
    }

    fn new_with_depth(depth: usize) -> Self {
        if depth == 0 {
            return BalancedBinaryTree::new_empty();
        }
        let node = BalancedBinaryTree::new_with_depth(depth - 1);
        BalancedBinaryTree { value: None, left: Some(Box::new(node.clone())), right: Some(Box::new(node)) }
    }

    fn from_vec_with_paths(items: Vec<(Vec<T>, Path)>) -> Self
    where
        T: Clone + Default + Debug,
    {
        if items.is_empty() {
            return BalancedBinaryTree::new_empty();
        }

        let mut root = BalancedBinaryTree::new_empty();

        for (values, path) in items {
            let mut current = &mut root;
            current.value = Some(values.first().expect("No value in values").clone());

            for (direction, value) in path.into_iter().zip(values.into_iter().skip(1)) {
                match direction {
                    Direction::Left => {
                        if current.left.is_none() {
                            current.left = Some(Box::new(BalancedBinaryTree::new_empty()));
                        }
                        current = current.left.as_mut().unwrap();
                    }
                    Direction::Right => {
                        if current.right.is_none() {
                            current.right = Some(Box::new(BalancedBinaryTree::new_empty()));
                        }
                        current = current.right.as_mut().unwrap();
                    }
                }
                current.value = Some(value.clone());
            }
        }

        root
    }

    fn height(&self) -> usize {
        fn calculate_height<T>(node: &Option<Box<BalancedBinaryTree<T>>>) -> usize {
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

    fn get_leaf(&self, index: usize) -> Option<&T> {
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

    fn get(&self, path: &Path) -> Option<&T> {
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

    fn get_all_nodes_along_path(&self, path: &Path) -> Vec<T> {
        let mut current = self;
        let mut nodes = vec![];

        if let Some(value) = current.value.as_ref() {
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
            if let Some(value) = current.value.as_ref() {
                nodes.push(value.clone());
            }
        }

        nodes
    }

    fn lca(&mut self, path: &Path) -> Option<(&mut T, Path)> {
        let mut current = self;
        let mut current_path = Path::new(Vec::new());
        
        for &direction in path {
            match direction {
                Direction::Left => {
                    if let Some(left) = current.left.as_mut() {
                        current = left;
                        current_path.push(Direction::Left);
                    } else {
                        return current.value.as_mut().map(|v| (v, current_path));
                    }
                }
                Direction::Right => {
                    if let Some(right) = current.right.as_mut() {
                        current = right;
                        current_path.push(Direction::Right);
                    } else {
                        return current.value.as_mut().map(|v| (v, current_path));
                    }
                }
            }
            
            if current.left.is_none() && current.right.is_none() {
                return current.value.as_mut().map(|v| (v, current_path));
            }
        }
        
        current.value.as_mut().map(|v| (v, current_path))
    }

    fn write(&mut self, value: T, path: Path) {
        let mut current = self;
        for direction in path {
            match direction {
                Direction::Left => {
                    if current.left.is_none() {
                        current.left = Some(Box::new(BalancedBinaryTree::new_empty()));
                    }
                    current = current.left.as_mut().unwrap();
                }
                Direction::Right => {
                    if current.right.is_none() {
                        current.right = Some(Box::new(BalancedBinaryTree::new_empty()));
                    }
                    current = current.right.as_mut().unwrap();
                }
            }
        }
    
        current.value = Some(value);
    }

    fn overwrite_tree(&mut self, other: &BalancedBinaryTree<T>) {
        if let Some(value) = &other.value {
            self.value = Some(value.clone());
        }
        if let Some(left) = &other.left {
            if self.left.is_none() {
                self.left = Some(Box::new(BalancedBinaryTree::new_empty()));
            }
            self.left.as_mut().unwrap().overwrite_tree(left);
        }
        if let Some(right) = &other.right {
            if self.right.is_none() {
                self.right = Some(Box::new(BalancedBinaryTree::new_empty()));
            }
            self.right.as_mut().unwrap().overwrite_tree(right);
        }
    }

    fn flatten_tree(&self) -> Vec<(T, Path)> {
        let mut flattened = Vec::new();
        Self::_flatten_tree(self, Path::new(vec![]), &mut flattened);
        flattened
    }

    fn zip<S: Clone>(&self, rhs: &impl BinaryTree<S>) -> Vec<(Option<T>, Option<S>, Path)> where Self: Sized {
        let mut result = Vec::new();
        Self::_zip(&Some(Box::new(self.clone())), &Some(Box::new(rhs.clone())), Path::new(vec![]), &mut result);
        result
    }
}

impl<T: Clone> BalancedBinaryTree<T> {
    fn _flatten_tree(node: &BalancedBinaryTree<T>, path: Path, flattened: &mut Vec<(T, Path)>) {
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
        if let Some(value) = &node.value {
            flattened.push((value.clone(), path.clone()));
        }
    }
}

impl<T: fmt::Debug> fmt::Display for BalancedBinaryTree<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn print_tree<T: fmt::Debug>(
            node: &BalancedBinaryTree<T>,
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

impl<T: Clone> BalancedBinaryTree<T> {
    fn _zip<S: Clone>(lhs: &Option<Box<BalancedBinaryTree<T>>>, rhs: &Option<Box<BalancedBinaryTree<S>>>, path: Path, flattened: &mut Vec<(Option<T>, Option<S>, Path)>) {
        match (lhs, rhs) {
            (Some(lhs), Some(rhs)) => {
                if lhs.value.is_some() {
                    flattened.push((lhs.value.clone(), rhs.value.clone(), path.clone()));
                }

                if let (Some(left_lhs), Some(left_rhs)) = (&lhs.left, &rhs.left) {
                    let mut left_path = path.clone();
                    left_path.push(Direction::Left);
                    Self::_zip(&Some(left_lhs.clone()), &Some(left_rhs.clone()), left_path, flattened);
                }
                else if let (Some(left_lhs), None) = (&lhs.left, &rhs.left) {
                    let mut left_path = path.clone();
                    left_path.push(Direction::Left);
                    Self::_zip(&Some(left_lhs.clone()), &None, left_path, flattened);
                }

                if let (Some(right_lhs), Some(right_rhs)) = (&lhs.right, &rhs.right) {
                    let mut right_path = path.clone();
                    right_path.push(Direction::Right);
                    Self::_zip(&Some(right_lhs.clone()), &Some(right_rhs.clone()), right_path, flattened);
                }
                else if let (Some(right_lhs), None) = (&lhs.right, &rhs.right) {
                    let mut right_path = path.clone();
                    right_path.push(Direction::Right);
                    Self::_zip(&Some(right_lhs.clone()), &None, right_path, flattened);
                }

            },
            (Some(lhs), None) => {
                if lhs.value.is_some() {
                    flattened.push((lhs.value.clone(), None, path.clone()));
                }
                if let Some(left_lhs) = &lhs.left {
                    let mut left_path = path.clone();
                    left_path.push(Direction::Left);
                    Self::_zip(&Some(left_lhs.clone()), &None, left_path, flattened);
                }
                if let Some(right_lhs) = &lhs.right {
                    let mut right_path = path.clone();
                    right_path.push(Direction::Right);
                    Self::_zip(&Some(right_lhs.clone()), &None, right_path, flattened);
                }
            }
            (None, Some(_)) | (None, None) => (),
        }
    }
}