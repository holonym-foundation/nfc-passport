pragma circom 2.1.5;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "./helpers/extract.circom";
include "./passport_verifier.circom";
include "./merkle-proof.circom";


// This verifies a passport has a particular nullifier and its issuer is part of a Merkle root of allowed issuers
template ProofOfPassport(n, k, MAX_DEPTH) {
    signal input depth, indices[MAX_DEPTH], siblings[MAX_DEPTH]; // binary merkle tree proof
    // signal input mrz[93]; // formatted mrz (5 + 88) chars
    // signal input dataHashes[297];
    // signal input eContentBytes[104];
    signal input eContentSha[256];
    signal input pubkey[k];
    signal input signature[k];

    // signal input reveal_bitmap[88];
    // signal input address;

    // Verify passport
    component PV = PassportVerifier(n, k);
    // PV.mrz <== mrz;
    // PV.dataHashes <== dataHashes;
    PV.eContentSha <== eContentSha;
    PV.pubkey <== pubkey;
    PV.signature <== signature;

    // // reveal reveal_bitmap bits of MRZ
    // signal reveal[88];
    // for (var i = 0; i < 88; i++) {
    //     reveal[i] <== mrz[5+i] * reveal_bitmap[i];
    // }
    // signal output reveal_packed[3] <== PackBytes(88, 3, 31)(reveal);


    // make nullifier public;
    // we take nullifier = signature[0, 1] which it 64 + 64 bits long, so chance of collision is 2^128
    signal output nullifier <== signature[0] * 2**64 + signature[1];
    
    signal pubkey_packed[11];
    for (var i = 0; i < 11; i++) {
        if (i < 10) {
            pubkey_packed[i] <== pubkey[3*i] * 64 * 64 + pubkey[3*i + 1] * 64 + pubkey[3*i + 2];
        } else {
            pubkey_packed[i] <== pubkey[3*i] * 64 * 64;
        }
    }
    
    component pubkey_hash = Poseidon(11);

    signal pubkey_digest; 
    for (var i = 0; i < 11; i++) {
        pubkey_hash.inputs[i] <== pubkey_packed[i];
    }
    pubkey_digest <== pubkey_hash.out;

    // Prove set membership of issuer public key
    signal output root <== BinaryMerkleRoot(MAX_DEPTH)(pubkey_digest, depth, indices, siblings);
    
}

component main = ProofOfPassport(64, 32, 15);


