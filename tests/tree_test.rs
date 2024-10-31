use myco_rs::tree::{BinaryTree, TreeValue};
use myco_rs::dtypes::{Direction, Path};
use rand_chacha::ChaCha20Rng;

#[cfg(test)]
mod tree_tests {
    use rand::{Rng, SeedableRng};

    use super::*;

    #[derive(Default, Debug, Clone, PartialEq)]
    struct IntWrapper(i32);

    impl TreeValue for IntWrapper {
        fn new_random() -> Self {
            let mut rng = ChaCha20Rng::from_entropy();
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
        assert_eq!(tree.value[1], Some(IntWrapper(42)));

        // Test creating a tree with depth
        let tree_with_depth = BinaryTree::<IntWrapper>::new_with_depth(2);
        assert_eq!(tree_with_depth.height(), 2);
    }

    #[test]
    fn test_get() {
        // Create a tree with some values, including non-leaf nodes
        let items = vec![
            (
                vec![
                    IntWrapper(0),
                    IntWrapper(1),
                    IntWrapper(2),
                    IntWrapper(3),
                    IntWrapper(1),
                ],
                Path::new(vec![
                    Direction::Left,
                    Direction::Left,
                    Direction::Left,
                    Direction::Left,
                ]),
            ),
            (
                vec![
                    IntWrapper(0),
                    IntWrapper(1),
                    IntWrapper(2),
                    IntWrapper(3),
                    IntWrapper(2),
                ],
                Path::new(vec![
                    Direction::Left,
                    Direction::Left,
                    Direction::Right,
                    Direction::Right,
                ]),
            ),
            (
                vec![
                    IntWrapper(0),
                    IntWrapper(1),
                    IntWrapper(2),
                    IntWrapper(3),
                    IntWrapper(3),
                ],
                Path::new(vec![
                    Direction::Left,
                    Direction::Right,
                    Direction::Left,
                    Direction::Left,
                ]),
            ),
            (
                vec![
                    IntWrapper(0),
                    IntWrapper(1),
                    IntWrapper(2),
                    IntWrapper(3),
                    IntWrapper(4),
                ],
                Path::new(vec![
                    Direction::Right,
                    Direction::Left,
                    Direction::Left,
                    Direction::Left,
                ]),
            ),
            (
                vec![
                    IntWrapper(0),
                    IntWrapper(1),
                    IntWrapper(2),
                    IntWrapper(3),
                    IntWrapper(5),
                ],
                Path::new(vec![
                    Direction::Right,
                    Direction::Left,
                    Direction::Right,
                    Direction::Right,
                ]),
            ),
            (
                vec![
                    IntWrapper(0),
                    IntWrapper(1),
                    IntWrapper(2),
                    IntWrapper(3),
                    IntWrapper(6),
                ],
                Path::new(vec![
                    Direction::Right,
                    Direction::Right,
                    Direction::Left,
                    Direction::Left,
                ]),
            ),
            (
                vec![
                    IntWrapper(0),
                    IntWrapper(1),
                    IntWrapper(2),
                    IntWrapper(3),
                    IntWrapper(7),
                ],
                Path::new(vec![
                    Direction::Right,
                    Direction::Right,
                    Direction::Right,
                    Direction::Left,
                ]),
            ),
            (
                vec![
                    IntWrapper(0),
                    IntWrapper(1),
                    IntWrapper(2),
                    IntWrapper(3),
                    IntWrapper(8),
                ],
                Path::new(vec![
                    Direction::Right,
                    Direction::Right,
                    Direction::Right,
                    Direction::Right,
                ]),
            ),
        ];
        let tree = BinaryTree::from_vec_with_paths(items);

        // Test get method for existing paths
        assert_eq!(
            tree.get(&Path::new(vec![
                Direction::Left,
                Direction::Left,
                Direction::Left,
                Direction::Left,
            ])),
            Some(IntWrapper(1))
        );
        assert_eq!(
            tree.get(&Path::new(vec![
                Direction::Left,
                Direction::Left,
                Direction::Right,
                Direction::Right
            ])),
            Some(IntWrapper(2))
        );
        assert_eq!(
            tree.get(&Path::new(vec![
                Direction::Right,
                Direction::Right,
                Direction::Right,
                Direction::Right
            ])),
            Some(IntWrapper(8))
        );

        // Test get method for non-leaf nodes
        assert_eq!(
            tree.get(&Path::new(vec![Direction::Left])),
            Some(IntWrapper(1))
        );
        assert_eq!(
            tree.get(&Path::new(vec![Direction::Right, Direction::Left])),
            Some(IntWrapper(2))
        );

        // Test get method for root
        assert_eq!(tree.get(&Path::new(vec![])), Some(IntWrapper(0)));

        // Test get method for non-existing paths
        assert_eq!(
            tree.get(&Path::new(vec![
                Direction::Left,
                Direction::Left,
                Direction::Left,
                Direction::Right
            ])),
            None
        );
        assert_eq!(
            tree.get(&Path::new(vec![
                Direction::Right,
                Direction::Right,
                Direction::Left,
                Direction::Right
            ])),
            None
        );
        assert_eq!(
            tree.get(&Path::new(vec![
                Direction::Left,
                Direction::Right,
                Direction::Right,
                Direction::Right
            ])),
            None
        );
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
            (
                vec![IntWrapper(7), IntWrapper(5)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(7), IntWrapper(6)],
                Path::new(vec![Direction::Right]),
            ),
            (
                vec![IntWrapper(7), IntWrapper(5), IntWrapper(1)],
                Path::new(vec![Direction::Left, Direction::Left]),
            ),
            (
                vec![IntWrapper(7), IntWrapper(5), IntWrapper(2)],
                Path::new(vec![Direction::Left, Direction::Right]),
            ),
            (
                vec![IntWrapper(7), IntWrapper(6), IntWrapper(3)],
                Path::new(vec![Direction::Right, Direction::Left]),
            ),
            (
                vec![IntWrapper(7), IntWrapper(6), IntWrapper(4)],
                Path::new(vec![Direction::Right, Direction::Right]),
            ),
        ];
        let mut tree = BinaryTree::from_vec_with_paths(items);

        // Test lca with various paths
        let path1 = Path::new(vec![Direction::Left, Direction::Left]);
        assert_eq!(tree.lca(&path1), Some((&mut IntWrapper(1), path1.clone())));

        let path2 = Path::new(vec![Direction::Right, Direction::Right]);
        assert_eq!(tree.lca(&path2), Some((&mut IntWrapper(4), path2.clone())));

        let path3 = Path::new(vec![]);
        assert_eq!(tree.lca(&path3), Some((&mut IntWrapper(7), path3.clone())));

        let path4 = Path::new(vec![Direction::Left]);
        assert_eq!(tree.lca(&path4), Some((&mut IntWrapper(5), path4.clone())));

        let path5 = Path::new(vec![Direction::Left, Direction::Right, Direction::Left]);
        assert_eq!(
            tree.lca(&path5),
            Some((
                &mut IntWrapper(2),
                Path::new(vec![Direction::Left, Direction::Right])
            ))
        );

        let path6 = Path::new(vec![Direction::Right, Direction::Left, Direction::Left]);
        assert_eq!(
            tree.lca(&path6),
            Some((
                &mut IntWrapper(3),
                Path::new(vec![Direction::Right, Direction::Left])
            ))
        );
    }

    #[test]
    fn test_new_with_depth_zero() {
        // Create a binary tree with depth 0
        let tree = BinaryTree::<IntWrapper>::new_with_depth(0);

        // Define the expected tree: a single root node with no children
        let expected = BinaryTree::<IntWrapper>::new_empty();

        // Assert that the created tree matches the expected tree
        assert_eq!(
            tree.height(),
            expected.height(),
            "A tree with depth 0 should have height 0"
        );
        assert_eq!(
            tree.value, expected.value,
            "A tree with depth 0 should have the same value as an empty tree"
        );
    }

    #[test]
    fn test_new_with_depth_large() {
        // Create a binary tree with a larger depth
        let depth = 4;
        let tree = BinaryTree::<IntWrapper>::new_with_depth(depth);

        // The expected number of nodes for a binary tree of depth d is 2^(d) - 1
        let expected_nodes = 2_usize.pow((depth + 1) as u32);
        let actual_nodes = tree.value.len();

        // Assert that the number of nodes matches the expected count
        assert_eq!(
            actual_nodes, expected_nodes,
            "A tree with depth {} should have {} nodes, but found {}",
            depth, expected_nodes, actual_nodes
        );
    }

    #[test]
    fn test_get_all_nodes_along_path() {
        // Create a binary tree for testing:
        //         7
        //        / \
        //       5   6
        //      / \   \
        //     1   2   3
        let tree = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(7)], Path::new(vec![])),
            (
                vec![IntWrapper(7), IntWrapper(5)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(7), IntWrapper(6)],
                Path::new(vec![Direction::Right]),
            ),
            (
                vec![IntWrapper(7), IntWrapper(5), IntWrapper(1)],
                Path::new(vec![Direction::Left, Direction::Left]),
            ),
            (
                vec![IntWrapper(7), IntWrapper(5), IntWrapper(2)],
                Path::new(vec![Direction::Left, Direction::Right]),
            ),
            (
                vec![IntWrapper(7), IntWrapper(6), IntWrapper(3)],
                Path::new(vec![Direction::Right, Direction::Right]),
            ),
        ]);

        // Define paths and their expected node values
        let test_cases = vec![
            // Test case 1: Empty path should return only the root
            (
                Path::new(vec![]),
                vec![IntWrapper(7)],
                "Empty path should return only the root node",
            ),
            // Test case 2: Path to the left child
            (
                Path::new(vec![Direction::Left]),
                vec![IntWrapper(7), IntWrapper(5)],
                "Path [Left] should return the root and left child",
            ),
            // Test case 3: Path to the right child
            (
                Path::new(vec![Direction::Right]),
                vec![IntWrapper(7), IntWrapper(6)],
                "Path [Right] should return the root and right child",
            ),
            // Test case 4: Path to the left-left grandchild
            (
                Path::new(vec![Direction::Left, Direction::Left]),
                vec![IntWrapper(7), IntWrapper(5), IntWrapper(1)],
                "Path [Left, Left] should return the root, left child, and left-left grandchild",
            ),
            // Test case 5: Path to the left-right grandchild
            (
                Path::new(vec![Direction::Left, Direction::Right]),
                vec![IntWrapper(7), IntWrapper(5), IntWrapper(2)],
                "Path [Left, Right] should return the root, left child, and left-right grandchild",
            ),
            // Test case 6: Path to the right-right grandchild
            (
                Path::new(vec![Direction::Right, Direction::Right]),
                vec![IntWrapper(7), IntWrapper(6), IntWrapper(3)],
                "Path [Right, Right] should return the root, right child, and right-right grandchild",
            ),
            // Test case 7: Path that partially exists (non-existent node)
            (
                Path::new(vec![Direction::Right, Direction::Left]),
                vec![IntWrapper(7), IntWrapper(6)],
                "Path [Right, Left] should return only existing nodes up to where the path breaks",
            ),
            // Test case 8: Longer path with non-existent nodes
            (
                Path::new(vec![Direction::Left, Direction::Left, Direction::Left]),
                vec![IntWrapper(7), IntWrapper(5), IntWrapper(1)],
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
    fn test_overwrite_tree_basic() {
        // Create the original tree
        // Structure:
        //      1
        //     / \
        //    2   3
        let mut original = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(1)], Path::new(vec![])), // Root
            (
                vec![IntWrapper(1), IntWrapper(2)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(1), IntWrapper(3)],
                Path::new(vec![Direction::Right]),
            ),
        ]);

        // Create the other tree to overwrite with
        // Structure:
        //      4
        //     / \
        //    5   6
        let other = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root
            (
                vec![IntWrapper(4), IntWrapper(5)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(4), IntWrapper(6)],
                Path::new(vec![Direction::Right]),
            ),
        ]);

        // Perform the overwrite
        original.overwrite(&other);

        // Define the expected tree after overwrite
        let expected = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root overwritten
            (
                vec![IntWrapper(4), IntWrapper(5)],
                Path::new(vec![Direction::Left]),
            ), // Left child overwritten
            (
                vec![IntWrapper(4), IntWrapper(6)],
                Path::new(vec![Direction::Right]),
            ), // Right child overwritten
        ]);

        // Assert that the original tree now matches the expected tree
        assert_eq!(
            original, expected,
            "The tree was not correctly overwritten with the other tree"
        );
    }

    #[test]
    fn test_overwrite_tree_with_empty_other() {
        // Create the tree to be overwritten
        let mut original = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(1)], Path::new(vec![])), // Root
            (
                vec![IntWrapper(1), IntWrapper(2)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(1), IntWrapper(3)],
                Path::new(vec![Direction::Right]),
            ),
        ]);

        // Create an empty tree to overwrite with
        let other: BinaryTree<IntWrapper> = BinaryTree::new_empty();

        // Perform the overwrite
        original.overwrite(&other);

        // Define the expected tree after overwrite (should remain unchanged)
        let expected = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(1)], Path::new(vec![])), // Root
            (
                vec![IntWrapper(1), IntWrapper(2)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(1), IntWrapper(3)],
                Path::new(vec![Direction::Right]),
            ),
        ]);

        // Assert that the original tree remains unchanged
        assert_eq!(
            original, expected,
            "Overwriting with an empty tree should not alter the original tree"
        );
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
            (
                vec![IntWrapper(4), IntWrapper(5)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(4), IntWrapper(6)],
                Path::new(vec![Direction::Right]),
            ),
        ]);

        // Perform the overwrite
        original.overwrite(&other);

        // Define the expected tree after overwrite
        let expected = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root
            (
                vec![IntWrapper(4), IntWrapper(5)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(4), IntWrapper(6)],
                Path::new(vec![Direction::Right]),
            ),
        ]);

        // Assert that the original tree now matches the expected tree
        assert_eq!(
            original, expected,
            "Overwriting an empty tree with another tree should result in the other tree"
        );
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
            (
                vec![IntWrapper(1), IntWrapper(2)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(1), IntWrapper(2), IntWrapper(3)],
                Path::new(vec![Direction::Left, Direction::Left]),
            ),
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
            (
                vec![IntWrapper(4), IntWrapper(5)],
                Path::new(vec![Direction::Right]),
            ),
            (
                vec![IntWrapper(4), IntWrapper(5), IntWrapper(6)],
                Path::new(vec![Direction::Right, Direction::Right]),
            ),
        ]);

        // Perform the overwrite
        original.overwrite(&other);

        // Define the expected tree after overwrite
        let expected = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root overwritten
            (
                vec![IntWrapper(4), IntWrapper(2)],
                Path::new(vec![Direction::Left]),
            ), // Existing left child remains
            (
                vec![IntWrapper(4), IntWrapper(2), IntWrapper(3)],
                Path::new(vec![Direction::Left, Direction::Left]),
            ), // Existing left-left child remains
            (
                vec![IntWrapper(4), IntWrapper(5)],
                Path::new(vec![Direction::Right]),
            ), // Right child added
            (
                vec![IntWrapper(4), IntWrapper(5), IntWrapper(6)],
                Path::new(vec![Direction::Right, Direction::Right]),
            ), // Right-Right child added
        ]);

        // Assert that the original tree now matches the expected tree
        assert_eq!(
            original, expected,
            "Overwriting with a tree of a different structure did not result in the expected tree"
        );
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
            (
                vec![IntWrapper(1), IntWrapper(2)],
                Path::new(vec![Direction::Left]),
            ),
            (
                vec![IntWrapper(1), IntWrapper(3)],
                Path::new(vec![Direction::Right]),
            ),
        ]);

        // Create the other tree to overwrite with
        // Structure:
        //      4
        //     /
        //    5
        let other = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root
            (
                vec![IntWrapper(4), IntWrapper(5)],
                Path::new(vec![Direction::Left]),
            ), // Overwrites left child
        ]);

        // Perform the overwrite
        original.overwrite(&other);

        // Define the expected tree after overwrite
        let expected = BinaryTree::from_vec_with_paths(vec![
            (vec![IntWrapper(4)], Path::new(vec![])), // Root overwritten
            (
                vec![IntWrapper(4), IntWrapper(5)],
                Path::new(vec![Direction::Left]),
            ), // Left child overwritten
            (
                vec![IntWrapper(4), IntWrapper(3)],
                Path::new(vec![Direction::Right]),
            ), // Right child remains unchanged
        ]);

        // Assert that the original tree now matches the expected tree
        assert_eq!(
            original, expected,
            "Overwriting with a tree that partially overlaps did not result in the expected tree"
        );
    }
}
