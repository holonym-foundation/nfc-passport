import { buildPoseidon } from "circomlibjs"
import issuers from "../NFC passport public key verifier government.json"
import { IncrementalMerkleTree } from "@zk-kit/incremental-merkle-tree"
import { existsSync, readFileSync, writeFileSync } from "fs";

export const ISSUER_TREE_DEPTH = 15;

let poseidon;
let issuerTree;

async function getPoseidon() { 
  if(!poseidon) { poseidon = await buildPoseidon() }
  return (x) => poseidon.F.toString(poseidon(x))
}

export type MerkleProof = {
  leaf: bigint;
  siblings: bigint[][];
  pathIndices: number[];
}
// Loads a merkle tree of all the issuer public keys and creates a proof for a given index, without having to reconstruct the tree
export class PrecomputedBinaryMerkleTree {
  nodes: bigint[][];
  constructor(nodes: bigint[][]) {
    this.nodes = nodes;
  }
  createProof: (index: number) => MerkleProof = (index: number): MerkleProof => {
    let curIdx = index;
    let pathIndices = [];
    let siblings = [];
    for (let i = 0; i < ISSUER_TREE_DEPTH; i++) {
      if (curIdx % 2 == 0) {
        pathIndices.push(0)
        siblings.push([this.nodes[i][curIdx + 1]])
      } else {
        pathIndices.push(1)
        siblings.push([this.nodes[i][curIdx - 1]])
      }
      curIdx = Math.floor(curIdx / 2)
    }
    return {
      leaf: this.nodes[0][index],
      siblings: siblings,
      pathIndices: pathIndices
    }
  };


}

export async function generateModulusHashes() {
  let p = await getPoseidon();
  let modulusHashes = [];
  await issuers["issuers"].forEach(async (obj) => {
    if(obj['modulus']) {
      modulusHashes.push(await hashPubkey(obj['modulus']))
    }
  });
  return modulusHashes;
}
async function saveModulusHashes() { 
  let modulusHashes = await generateModulusHashes();
  writeFileSync('modulusHashes.json', JSON.stringify(modulusHashes))
}
async function loadModulusHashes(): Promise<string[]> { 
  if (!existsSync('modulusHashes.json')) {
      await saveModulusHashes()
  } 
  return JSON.parse(readFileSync('modulusHashes.json').toString())
}

async function generateIssuerTree() {
  let p = await getPoseidon();
  let issuerTree = new IncrementalMerkleTree(p, ISSUER_TREE_DEPTH, BigInt(0), 2) // Binary poseidon merkle tree of depth 10 and default value 0
    // fill the tree with the hash of their moduli
    let modulusHashes = await loadModulusHashes();
    modulusHashes.forEach((hash) => {issuerTree.insert(hash)})
    return issuerTree
}
export async function loadIsssuerTree(): Promise<PrecomputedBinaryMerkleTree> {  
    let p = await getPoseidon();
    if (!existsSync('issuerTree.json')) {
      await saveIssuerTree()
    }
    const nodes = JSON.parse(readFileSync('issuerTree.json').toString());
    return new PrecomputedBinaryMerkleTree(nodes.map((node) => node.map((n) => BigInt(n))))
}

export async function saveIssuerTree() {
  const issuerTree = await generateIssuerTree();
  writeFileSync('issuerTree.json', JSON.stringify(
    issuerTree._nodes.map(level => level.map(n => {
      if (n instanceof ArrayBuffer) {
        return BigInt('0x'+Buffer.from(n).toString('hex')).toString()
      } else {
        return n.toString()
      }
    }))
  ))
}

// break a 2048-bit number into 11 field elements in the same way the circuit does
function packPubkey(pubkey: BigInt) {
  const sixtyFour = BigInt(64);
  // to 64-bit chunks
  const parts = pubkey.toString(16).match(/.{1,8}/g);
  let pubkeyPacked = [];
  for (var i = 0; i < 11; i++) {
    if (i < 10) {
      pubkeyPacked.push(BigInt('0x'+parts.at(3*i)) * sixtyFour * sixtyFour + BigInt('0x'+parts.at(3*i + 1)) * sixtyFour + BigInt('0x'+parts.at(3*i + 2)));
    } else {
      pubkeyPacked.push(BigInt('0x'+parts.at(3*i)) * sixtyFour * sixtyFour);
    }
  }
  return pubkeyPacked;
}
  
export async function hashPubkey(pubkey: string): Promise<string> {
  let poseidon = await getPoseidon();
  return poseidon(packPubkey(BigInt(pubkey)))
}
