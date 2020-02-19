package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const(
	LeftBranch = "L"
	RightBranch = "R"
)

type Node struct {
	hash string
	value string
	parent, leftChild, rightChild *Node
}

func (node Node) IsLeaf() bool {
	return node.leftChild == nil && node.rightChild == nil
}

func (node Node) ToString() string {
	if node.IsLeaf() {
		return node.value + " - " + node.hash
	}
	return node.hash
}

type MerkleTree struct {
	root Node
	leaves []*Node
}

func (tree MerkleTree) GetAuditTrial(target_hash string) [][]string {
	for _, leaf := range tree.leaves {
		if leaf.hash == target_hash {
			var trail [][]string
			return tree.GenerateAuditTrial(leaf, trail)
		}
	}
	return nil
}

func (tree MerkleTree) GenerateAuditTrial(node *Node, trail [][]string) [][]string {
	if tree.root == *node {
		return trail
	}
	if *node.parent.leftChild == *node {
		path := make([]string, 2)
		path[0] = node.parent.rightChild.hash
		path[1] = RightBranch
		trail = append(trail, path)
	} else {
		path := make([]string, 2)
		path[0] = node.parent.leftChild.hash
		path[1] = LeftBranch
		trail = append(trail, path)
	}
	return tree.GenerateAuditTrial(node.parent, trail)
}

func ChunkData(data string) []string {
	return strings.Split(data, " ")
}

func ComputeHash(data string) string {
	hash_bytes := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash_bytes[:])
}

func BuildTree(chunks []string) MerkleTree {
	leaves := BuildLeaves(chunks)
	root := BuildParents(leaves)
	return MerkleTree{root, leaves}
}

func BuildLeaves(chunks []string) []*Node {
	var leaves []*Node
	for _, chunk := range chunks {
		leaves = append(leaves, &Node{ComputeHash(chunk), chunk,nil, nil, nil})
	}
	return leaves
}

func BuildParents(leaves []*Node) Node {
	num_leaves := len(leaves)
	if num_leaves == 1 {
		return *leaves[0]
	}
	var parents []*Node
	i := 0
	for i < num_leaves {
		leftChild, rightChild := &leaves[i], &leaves[i]
		if i + 1 < num_leaves {
			rightChild = &leaves[i + 1]
		}
		parent := Node{ComputeHash((*leftChild).hash + (*rightChild).hash), "",nil, nil, nil}
		parent.leftChild, parent.rightChild = *leftChild, *rightChild
		(*leftChild).parent, (*rightChild).parent = &parent, &parent
		parents = append(parents, &parent)
		i += 2
	}
	return BuildParents(parents)
}

func PrintTree(node *Node, indent int) {
	if node == nil {
		return
	}
	fmt.Println(strings.Repeat(" ", indent), *node)
	indent += 2
	PrintTree(node.leftChild, indent)
	PrintTree(node.rightChild, indent)
}

func MerkleProof(trustedRootHash string, dataVerificationHash string, auditTrail [][]string) bool {
	currentHash := dataVerificationHash
	for _, item := range auditTrail {
		if item[1] == LeftBranch {
			currentHash = ComputeHash(item[0] + currentHash)
		} else {
			currentHash = ComputeHash(currentHash + item[0])
		}
	}
	return currentHash == trustedRootHash
}

func main() {
	data := "The quick brown fox jumps over the lazy dog who was sleeping under the oak tree"
	chunks := ChunkData(data)
	tree := BuildTree(chunks)
	fmt.Println("Printing the Merkle Tree ...")
	PrintTree(&tree.root, 0)

	dataVerificationHash := ComputeHash("brown")
	trustedRootHash := "bfddffb24e5f62ca7b157da0d88ed012545de73e1d3a5a5cc12838259cdc8109"

	fmt.Println("> Obtaining the audit trail for the data chunk 'brown' ...")
	auditTrail := tree.GetAuditTrial(dataVerificationHash)
	fmt.Println(auditTrail)

	fmt.Println("> Verifying the data chunk 'brown' against the root hash from a trusted source ...")
	if MerkleProof(trustedRootHash, dataVerificationHash, auditTrail) {
		fmt.Println("Data chunk verified successfully!")
	} else {
		fmt.Println("Data chunk failed verification!")
	}

	fmt.Println("> Verifying the corrupted data chunk 'jimp5' against the root hash from a trusted source ...")
	if MerkleProof(trustedRootHash, ComputeHash("jimp5"), auditTrail) {
		fmt.Println("Data chunk verified successfully!", "\n")
	} else {
		fmt.Println("Data chunk failed verification!", "\n")
	}
}
