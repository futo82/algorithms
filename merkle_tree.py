import enum

from hashlib import sha256


class Branch(enum.Enum):
    left = 1
    right = 2


class Node:
    def __init__(self, hash_value, data_value=None):
        self.hash_value = hash_value
        self.data_value = data_value
        self.parent = None
        self.left_child = None
        self.right_child = None

    def is_leaf(self):
        return self.left_child is None and self.right_child is None


class MerkleTree:
    def __init__(self, root_node, leaves):
        self.root_node = root_node
        self.leaves = leaves

    def get_audit_trail(self, target_leaf_hash):
        for leaf in self.leaves:
            if leaf.hash_value == target_leaf_hash:
                return self.generate_audit_trail(leaf)
        return None

    def generate_audit_trail(self, node, trail=[]):
        if self.root_node == node:
            trail.append((self.root_node.hash_value, None))
            return trail
        if node.parent.left_child == node:
            trail.append((node.parent.right_child.hash_value, Branch.right))
        else:
            trail.append((node.parent.left_child.hash_value, Branch.left))
        return self.generate_audit_trail(node.parent, trail)

    @staticmethod
    def build_tree(data_chunks):
        leaves = MerkleTree.build_leaves(data_chunks)
        root_node = MerkleTree.build_parents(leaves)
        return MerkleTree(root_node, leaves)

    @staticmethod
    def build_leaves(data_chunks):
        leaves = []
        for chunk in data_chunks:
            node = Node(compute_hash(chunk), chunk)
            leaves.append(node)
        return leaves

    @staticmethod
    def build_parents(leaves):
        num_leaves = len(leaves)
        if num_leaves == 1:
            return leaves[0]
        parents = []
        i = 0
        while i < num_leaves:
            left_child = leaves[i]
            # In the case of a odd number of leaves, we duplicate the last leaf hash value
            right_child = leaves[i + 1] if i + 1 < num_leaves else leaves[i]
            parent = Node(compute_hash(left_child.hash_value + right_child.hash_value))
            parent.left_child, parent.right_child = left_child, right_child
            left_child.parent, right_child.parent = parent, parent
            parents.append(parent)
            i += 2
        return MerkleTree.build_parents(parents)


def chunk_data(data):
    return data.split()


def compute_hash(data):
    return sha256(data.encode('utf-8')).hexdigest()


def print_tree(node, indent=0):
    if node is None:
        return
    if node.is_leaf():
        print((' ' * indent) + node.data_value + " - " + node.hash_value)
    else:
        print((' ' * indent) + node.hash_value)
    indent += 2
    print_tree(node.left_child, indent)
    print_tree(node.right_child, indent)


def merkle_proof(root_hash, leaf_hash, trail):
    current_hash = leaf_hash
    for item in trail[:-1]:
        if item[1] == Branch.left:
            current_hash = compute_hash(item[0] + current_hash)
        else:
            current_hash = compute_hash(current_hash + item[0])
    return current_hash == root_hash


# Build the Merkle Tree data structure from the bottom-up.
# The data is chunked into words.
data = 'The quick brown fox jumps over the lazy dog who was sleeping under the oak tree'
merkle_tree = MerkleTree.build_tree(chunk_data(data))

print("> Printing the Merkle Tree ...")
print_tree(merkle_tree.root_node)
print()

data_verification_hash = compute_hash("brown")
trusted_root_hash = 'bfddffb24e5f62ca7b157da0d88ed012545de73e1d3a5a5cc12838259cdc8109'

print("> Obtaining the audit trail for the data chunk 'brown' ...")
audit_trail = merkle_tree.get_audit_trail(data_verification_hash)
print(audit_trail, "\n")

print("> Verifying the data chunk 'brown' against the root hash from a trusted source ...")
if merkle_proof(trusted_root_hash, data_verification_hash, audit_trail):
    print("Data chunk verified successfully!", "\n")
else:
    print("Data chunk failed verification!", "\n")

print("> Verifying the corrupted data chunk 'jimp5' against the root hash from a trusted source ...")
data_verification_hash = compute_hash("jimp5")
if merkle_proof(trusted_root_hash, data_verification_hash, audit_trail):
    print("Data chunk verified successfully!", "\n")
else:
    print("Data chunk failed verification!", "\n")
