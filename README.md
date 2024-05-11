# EqualityStake
Hey guys, I have experimented a little bit with zk-SNARKs based on the Elliptic Curve Digital Signature Algorithm (ECDSA). 
A prover constructs a zero-knowledge proof demonstrating knowledge of the private key sk corresponding to a public key pk, without revealing sk. The verifier checks the proof's validity without learning sk.
Mathematically, the zk-SNARK proof system involves setting up quadratic equations encoding the ECDSA verification equation:
```plaintext
(g^r, pk) = e(g^s, P)
```
- `e`: a bilinear pairing operation
- `g`: an elliptic curve generator point
- `r`: the ECDSA signature
- `s`: the private key
- `P`: the public key

## zk-SNARK Proof System

The prover computes a witness `w` satisfying the equations and generates a zero-knowledge proof `π` demonstrating `w`'s existence without revealing it. The verifier checks `π`'s validity using public inputs.

## Merkle Trees and Authentication

Merkle trees are used to represent the set of authorized participants. Let `L = {l_1, l_2, ..., l_n}` be the leaves (participant identities). Leaf hashes `h_i` are computed using a hash function `H`. The Merkle tree is constructed by recursively hashing pairs of nodes:

```plaintext
parent = H(child_1 || child_2)
```

The root hash `r` commits to the entire leaf set.

A leaf `l_i`'s membership proof consists of sibling hashes needed to recompute `r` from `h_i`. Verification involves recomputing `r` from `h_i` and the provided sibling hashes, and checking if it matches the published `r`.
