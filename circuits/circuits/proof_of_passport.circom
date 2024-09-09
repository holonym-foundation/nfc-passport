pragma circom 2.1.5;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "./helpers/extract.circom";
include "./passport_verifier.circom";
include "./merkle-proof.circom";
include "./helpers/utils.circom";
include "./helpers/isValid.circom";

// include "@zk-email/circuits/utils/array.circom";
include "../node_modules/@zk-email/circuits/utils/array.circom";



// This verifies a passport has a particular nullifier and its issuer is part of a Merkle root of allowed issuers
template ProofOfPassport(n, k, MAX_DEPTH, max_datahashes_bytes) {
    signal input depth, indices[MAX_DEPTH], siblings[MAX_DEPTH]; // binary merkle tree proof
    // signal input eContentSha[256];
    signal input pubkey[k];
    signal input signature[k];


    signal input dg1_hash_offset;
    signal input dataHashes[max_datahashes_bytes];
    signal input datahashes_padded_length;
    signal input eContent[104];

    signal input currDate[6];
    signal input mrz[93];
    // User address to reveal
    signal input recipient;

    var hashLen = 32;
    var eContentBytesLength = 72 + hashLen; // 104


    // We test validity of passport based on its validity date
    component testValidity = IsValid();
    testValidity.currDate <== currDate;
    for (var i = 0; i < 6; i++) {
        testValidity.validityDateASCII[i] <== mrz[70 + i];
    }
    1 === testValidity.out;


    // We validate MRZ value
    // compute sha256 of formatted mrz
    signal mrzSha[256] <== Sha256BytesStatic(93)(mrz);

    // mrzSha_bytes: list of 32 Bits2Num
    component mrzSha_bytes[hashLen];

    // cast the 256 bits from mrzSha into a list of 32 bytes
    for (var i = 0; i < hashLen; i++) {
        mrzSha_bytes[i] = Bits2Num(8);

        for (var j = 0; j < 8; j++) {
            mrzSha_bytes[i].in[7 - j] <== mrzSha[i * 8 + j];
        }
    }

    // assert mrz_hash equals the one extracted from dataHashes input (bytes dg1_hash_offset to dg1_hash_offset + hashLen)
    signal dg1Hash[hashLen] <== SelectSubArray(max_datahashes_bytes, hashLen)(dataHashes, dg1_hash_offset, hashLen);
    for(var i = 0; i < hashLen; i++) {
        dg1Hash[i] === mrzSha_bytes[i].out;
    }

    // hash dataHashes dynamically
    signal dataHashesSha[256] <== Sha256Bytes(max_datahashes_bytes)(dataHashes, datahashes_padded_length);

    // get output of dataHashes sha256 into bytes to check against eContent
    component dataHashesSha_bytes[hashLen];
    for (var i = 0; i < hashLen; i++) {
        dataHashesSha_bytes[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            dataHashesSha_bytes[i].in[7 - j] <== dataHashesSha[i * 8 + j];
        }
    }

    // assert dataHashesSha is in eContentBytes in range bytes 72 to 104
    for(var i = 0; i < hashLen; i++) {
        eContentBytes[eContentBytesLength - hashLen + i] === dataHashesSha_bytes[i].out;
    }

    // hash eContentBytes
    signal eContentSha[256] <== Sha256BytesStatic(104)(eContentBytes);

    // get output of eContentBytes sha256 into k chunks of n bits each
    var msg_len = (256 + n) \ n;

    //eContentHash: list of length 256/n +1 of components of n bits 
    component eContentHash[msg_len];
    for (var i = 0; i < msg_len; i++) {
        eContentHash[i] = Bits2Num(n);
    }

    for (var i = 0; i < 256; i++) {
        eContentHash[i \ n].in[i % n] <== eContentSha[255 - i];
    }

    for (var i = 256; i < n * msg_len; i++) {
        eContentHash[i \ n].in[i % n] <== 0;
    }


    // No need to verify digest to be binary format anymore
    // for (var i=0; i<256; i++){
    //     eContentSha[i] * (eContentSha[i] - 1) === 0;
    // }

    component range_checks1[k];
    component range_checks2[k];
    for (var i=0; i<k; i++){
        range_checks1[i] = Num2Bits(64);
        range_checks2[i] = Num2Bits(64);
        range_checks1[i].in <== pubkey[i];
        range_checks2[i].in <== signature[i];
    }
    // signal input mrz[93]; // formatted mrz (5 + 88) chars
    // signal input dataHashes[297];
    // signal input eContentBytes[104];
    // signal input reveal_bitmap[88];
    // signal input address;

    // Verify passport
    component PV = PassportVerifier(n, k);
    // PV.mrz <== mrz;
    // PV.dataHashes <== dataHashes;
    PV.eContentSha <== eContentHash;
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
            pubkey_packed[i] <== pubkey[3*i] * 64 * 64 + pubkey[3*i + 1];
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
    
    // Constrain the recipient
    signal recipientSquared <== recipient * recipient;
}

component main { public [recipient] } = ProofOfPassport(64, 32, 15, 320);


