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
// import { prove, verify } from 'wasm-vole-zk-adapter-nodejs'
import { prove, verify } from 'wasm-vole-zk-adapter'

import dotenv from "dotenv"
import { ISSUER_TREE_DEPTH, generateModulusHashes, loadIsssuerTree, hashPubkey, ISSUER_MERKLE_ROOT } from '../scripts/issuerPubkeyUtils'
dotenv.config()
chai.use(chaiAsPromised)


// coneverts buffer to string of 0s and 1s
// main line from https://stackoverflow.com/a/66415563
function buf2bin (buffer) {
  let binString = BigInt('0x' + buffer.toString('hex')).toString(2).padStart(buffer.length * 8, '0')
  return Array.from(binString)
}

// JSON.stringify doesn't handle BigInts, so we need to convert them to strings
function toJSON(obj: any) {
  return JSON.stringify(obj, (key, value) =>
    typeof value === 'bigint'
        ? value.toString()
        : value // return everything else unchanged
  );
}

// urlCallbackData is the url-encoded data after the # in the callback url
// recipient is the ETH address of the recipient of the credential
async function makeProofInputs(urlCallbackData: string, recipient: string) {
  const [digest, sig, pubkey] = urlCallbackData.replaceAll('%2B','+').replaceAll('%2F','/').replaceAll('%3D','=').split(',').map(x => Buffer.from(x, 'base64'));
  const tree = await loadIsssuerTree();
  const issuer = await hashPubkey('0x'+pubkey.toString('hex'));
  const idx = tree.nodes[0].indexOf(BigInt(issuer));
  const proof = tree.createProof(idx);
  
  return  {
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
    eContentSha: buf2bin(digest),
    recipient
  }
}
async function makeProof(inputs) {
  fs.writeFileSync(`./proof_of_passport.inputs.json`, toJSON(inputs));
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

console.log("The following snarkjs error logs are normal and expected if the tests pass.")

describe('Circuit tests', function () {
  this.timeout(0)

  let inputs: any;

  this.beforeAll(async () => {
    inputs = await makeProofInputs(process.env.PASSPORT_DATA_FROM_CALLBACK_URL, "0x01234567890abcdef01234567890abcdef012345");    
  })
  
  describe('Proof', function() {
    it('test with local mock server', async function () {
      const proof = await makeProof(inputs);
      const res = await fetch("https://verifier.holonym.io/verify/0x0a/EPassportInCountryMerkleTree", {
      // const res = await fetch("http://localhost:3000/verify/0x0a/EPassportInCountryMerkleTree", {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream" },
        body: proof
      });

      console.log('res.text', await res.text());
      expect((await res.text()).startsWith(`{"values":{"circuit_id":"`)).to.be.true;
    });

    it('should prove and verify with valid inputs', async function () {
      const proof = await makeProof(inputs);
      fs.writeFileSync(`./proof_of_passport.proof`, proof);
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


