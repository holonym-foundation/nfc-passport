import { describe } from 'mocha'
import chai, { assert, expect } from 'chai'
import chaiAsPromised from 'chai-as-promised'
import { hash, toUnsignedByte, arraysAreEqual, bytesToBigDecimal, formatAndConcatenateDataHashes, formatMrz, splitToWords } from '../../common/src/utils/utils'
import { groth16 } from 'snarkjs'
import { DataHash } from '../../common/src/utils/types'
import { getPassportData } from '../../common/src/utils/passportData'
import { attributeToPosition } from '../../common/src/constants/constants'
import * as fs from 'fs';
import { WitnessCalculatorBuilder } from "circom_runtime";
import { prove, verify } from 'wasm-vole-zk-adapter-nodejs'

import dotenv from "dotenv"
import { ISSUER_TREE_DEPTH, generateModulusHashes, loadIsssuerTree, hashPubkey, ISSUER_MERKLE_ROOT } from '../scripts/issuerPubkeyUtils'
dotenv.config()

// coneverts buffer to string of 0s and 1s
// main line from https://stackoverflow.com/a/66415563
function buf2bin (buffer) {
  let binString = BigInt('0x' + buffer.toString('hex')).toString(2).padStart(buffer.length * 8, '0')
  return Array.from(binString)
}

chai.use(chaiAsPromised)

async function makeProof(inputs) {
  const r1cs = fs.readFileSync(`./proof_of_passport.r1cs`);
  const wasm = fs.readFileSync(`./proof_of_passport_js/proof_of_passport.wasm`);
  const wc = await WitnessCalculatorBuilder(wasm);
  let t = Date.now();
  const witness =  (wc.circom_version() == 1) ? await wc.calculateBinWitness(inputs) : await wc.calculateWTNSBin(inputs);
  console.log("Witness calculation time:", Date.now() - t);
  t = Date.now();
  const cnp = prove(r1cs, witness);  
  console.log("Proof generation time:", Date.now() - t);
  return cnp;
}
// async function verifyProof(cnp) {
//   const r1cs = fs.readFileSync(`./build/proof_of_passport.r1cs`);
//   return verify(r1cs, cnp);
// }

console.log("The following snarkjs error logs are normal and expected if the tests pass.")

describe('Circuit tests', function () {
  this.timeout(0)

  let inputs: any;

  this.beforeAll(async () => {
    // await generateModulusHashes();
    // What the user would see after the # in the silk passport callback url
    const [digest, sig, pubkey] = process.env.PASSPORT_DATA_FROM_CALLBACK_URL.replaceAll('%2B','+').replaceAll('%2F','/').replaceAll('%3D','=').split(',').map(x => Buffer.from(x, 'base64'));
    const tree = await loadIsssuerTree();
    const issuer = await hashPubkey('0x'+pubkey.toString('hex'));
    console.log('issuer', issuer)
    console.log('keys', Object.keys(tree))
    const idx = tree.nodes[0].indexOf(BigInt(issuer));
    console.log('idx', idx)
    const proof = tree.createProof(idx);
    // const passportData = getPassportData();
    // const formattedMrz = formatMrz(passportData.mrz);
    // console.log("passportData", 
    // formattedMrz,
    // passportData.dataGroupHashes as DataHash[]
    // )
    // const mrzHash = hash(formatMrz(passportData.mrz));
    // const concatenatedDataHashes = formatAndConcatenateDataHashes(
    //   mrzHash,
    //   passportData.dataGroupHashes as DataHash[],
    // );
    
    // const concatenatedDataHashesHashDigest = hash(concatenatedDataHashes);

    // assert(
    //   arraysAreEqual(passportData.eContent.slice(72, 72 + 32), concatenatedDataHashesHashDigest),
    //   'concatenatedDataHashesHashDigest is at the right place in passportData.eContent'
    // )

    // const reveal_bitmap = Array(88).fill('1');
    
    inputs = {
      // mrz: formattedMrz.map(byte => String(byte)),
      // reveal_bitmap: reveal_bitmap.map(byte => String(byte)),
      // dataHashes: concatenatedDataHashes.map(toUnsignedByte).map(byte => String(byte)),
      // eContentBytes: passportData.eContent.map(toUnsignedByte).map(byte => String(byte)),
      // leaf: proof.leaf,

      depth: ISSUER_TREE_DEPTH,
      indices: proof.pathIndices,//.map(idx => idx.toString()),
      siblings: proof.siblings,
      pubkey: splitToWords(
        BigInt('0x'+pubkey.toString('hex')),
        BigInt(64),
        BigInt(32)
      ),
      signature: splitToWords(
        BigInt('0x'+sig.toString('hex')),
        BigInt(64),
        BigInt(32)
      ),
      eContentSha: buf2bin(digest)
    }
    
  })
  
  describe('Proof', function() {
    it('should prove and verify with valid inputs', async function () {
      const proof = await makeProof(inputs);
      const r1cs = fs.readFileSync(`./proof_of_passport.r1cs`);
      const result = JSON.parse(await verify(r1cs, proof));
      console.log("result", result)
      await expect(makeProof(inputs)).to.not.be.rejected;
      expect(
        Buffer.from(result.public_outputs[1])
      ).to.deep.equal(
        Buffer.from(ISSUER_MERKLE_ROOT.toString(16), 'hex')
      );
    });

    it('invalid pubkey, digest, or signature should fail', async function () {
      const wrongPubkeyInputs = {...inputs}
      const wrongDigestInputs = {...inputs}
      const wrongSigInputs = {...inputs}

      wrongPubkeyInputs.pubkey[0] = (BigInt(wrongPubkeyInputs.pubkey[0]) + BigInt(1)).toString()
      wrongDigestInputs.eContentSha[0] = (BigInt(wrongDigestInputs.eContentSha[0]) + BigInt(1)).toString()
      wrongSigInputs.signature[0] = (BigInt(wrongSigInputs.signature[0]) + BigInt(1)).toString()

      await expect(makeProof(wrongPubkeyInputs)).to.be.rejected;
      await expect(makeProof(wrongDigestInputs)).to.be.rejected;
      await expect(makeProof(wrongSigInputs)).to.be.rejected;
      
    });

    // it('should fail to prove with invalid mrz', async function () {
    //   const invalidInputs = {
    //     ...inputs,
    //     mrz: inputs.mrz.map((byte: string) => String((parseInt(byte, 10) + 1) % 256)),
    //   }

    //   await expect(makeProof(invalidInputs)).to.be.rejected;
    // })

    // it('should fail to prove with invalid eContentBytes', async function () {
    //   const invalidInputs = {
    //     ...inputs,
    //     eContentBytes: inputs.eContentBytes.map((byte: string) => String((parseInt(byte, 10) + 1) % 256)),
    //   }

    //   await expect(makeProof(invalidInputs)).to.be.rejected;
    // })
    
    // it('should fail to prove with invalid signature', async function () {
    //   const invalidInputs = {
    //     ...inputs,
    //     signature: inputs.signature.map((byte: string) => String((parseInt(byte, 10) + 1) % 256)),
    //   }

    //   await expect(makeProof(invalidInputs)).to.be.rejected;
    // })
  
  // TODO: figure out how to do this test with wasm-vole-zk-adapter
    // it("shouldn't allow address maleability", async function () {
    //   const { proof, publicSignals } = await groth16.fullProve(
    //     inputs,
    //     "build/proof_of_passport_js/proof_of_passport.wasm",
    //     "build/proof_of_passport_final.zkey"
    //   )

    //   publicSignals[publicSignals.length - 1] = BigInt("0xC5B4F2A7Ea7F675Fca6EF724d6E06FFB40dFC93F").toString();

    //   const vKey = JSON.parse(fs.readFileSync("build/verification_key.json"));
    //   return expect(await groth16.verify(
    //     vKey,
    //     publicSignals,
    //     proof
    //   )).to.be.false;
    // })
  })

  // describe('Selective disclosure', function() {
  //   const attributeCombinations = [
  //     ['issuing_state', 'name'],
  //     ['passport_number', 'nationality', 'date_of_birth'],
  //     ['gender', 'expiry_date'],
  //   ];

  //   attributeCombinations.forEach(combination => {
  //     it(`Disclosing ${combination.join(", ")}`, async function () {
  //       const attributeToReveal = Object.keys(attributeToPosition).reduce((acc, attribute) => {
  //         acc[attribute] = combination.includes(attribute);
  //         return acc;
  //       }, {});
  
  //       const bitmap = Array(88).fill('0');

  //       Object.entries(attributeToReveal).forEach(([attribute, reveal]) => {
  //         if (reveal) {
  //           const [start, end] = attributeToPosition[attribute];
  //           bitmap.fill('1', start, end + 1);
  //         }
  //       });
  
  //       inputs = {
  //         ...inputs,
  //         reveal_bitmap: bitmap.map(String),
  //       }
  
  //       const publicSignals = JSON.parse(await verifyProof(makeProof(inputs)));
  //       console.log('proof verified');
  
  //       const firstThreeElements = publicSignals.slice(0, 3);
  //       const bytesCount = [31, 31, 26]; // nb of bytes in each of the first three field elements
  
  //       const bytesArray = firstThreeElements.flatMap((element: string, index: number) => {
  //         const bytes = bytesCount[index];
  //         const elementBigInt = BigInt(element);
  //         const byteMask = BigInt(255); // 0xFF
        
  //         const bytesOfElement = [...Array(bytes)].map((_, byteIndex) => {
  //           return (elementBigInt >> (BigInt(byteIndex) * BigInt(8))) & byteMask;
  //         });
        
  //         return bytesOfElement;
  //       });
        
  //       const result = bytesArray.map((byte: bigint) => String.fromCharCode(Number(byte)));
  
  //       console.log(result);
  
  //       for(let i = 0; i < result.length; i++) {
  //         if (bitmap[i] == '1') {
  //           const char = String.fromCharCode(Number(inputs.mrz[i + 5]));
  //           assert(result[i] == char, 'Should reveal the right one');
  //         } else {
  //           assert(result[i] == '\x00', 'Should not reveal');
  //         }
  //       }
  //     });
  //   });


  // })
})


