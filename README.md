# About
Based off of https://github.com/zk-passport, modified signifcantly for lightweight proof-of-personhood circuits with a lightweight merkle tree of verified countries, and fast proving with VOLE-based ZK

# How to use in frontend
1. Upload `issuerTree.json`, `proof_of_passport.r1cs`, and `proof_of_passport_js/proof_of_passport.wasm` so they are available to the frontend
2. Copy over `makeProofInputs` and `makeProof` from `passport.test.ts`, along with their imports and dependencies to the frontend
3. In issuerPubkey utils, you can ignore/delete all calls to `fs` and functions that are just to load and save files. rather, we can just directly make the PrecomputedBinaryMerkleTree from the contents of `issuerTree.json`. This may necessitate modifying 1-2 lines in `makeInputs` related to loading the Merkle tree.
4. replace package `wasm-vole-zk-adapter-nodejs` with `wasm-vole-zk-adapter`