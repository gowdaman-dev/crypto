const { ec } = require("elliptic");
const keccak256 = require("keccak");
const BigNumber = require("bignumber.js");
const bitcoin = require('bitcoinjs-lib');
const ECPairFactory = require('ecpair').ECPairFactory;
const tinysecp = require('tiny-secp256k1');

// // Create ECPair instance
const ECPair = ECPairFactory(tinysecp);
// Initialize secp256k1 elliptic curve
const secp256k1 = new ec("secp256k1");

// Define the private key range
const MIN_PRIVATE_KEY = new BigNumber("40000000000000000", 16); // Hexadecimal lower bound
const MAX_PRIVATE_KEY = new BigNumber("7ffffffffffffffff", 16); // Hexadecimal upper bound

// Convert a public key to an Ethereum-like address
function publicKeyToAddress(publicKeyHex) {
  // Remove the prefix '04' (uncompressed public key indicator)
  const publicKeyNoPrefix = publicKeyHex.slice(2);
  // Hash the public key using Keccak-256
  const hash = keccak256("keccak256")
    .update(Buffer.from(publicKeyNoPrefix, "hex"))
    .digest("hex");
  // Take the last 20 bytes (40 hex characters) of the hash
  return `0x${hash.slice(-40)}`;
}

// Generate a sequential private key, convert to public key, and derive address
function generateKeysAndAddress(privateKeyHex) {
  console.log(`Private Key: ${privateKeyHex}`);

  // Generate the public key from the private key
  const keyPair = secp256k1.keyFromPrivate(privateKeyHex, "hex");
  const publicKeyHex = keyPair.getPublic("hex");
  console.log(`Public Key: ${publicKeyHex}`);

  // Generate the address from the public key
  const address = publicKeyToAddress(publicKeyHex);
  console.log(`Address: ${address}`);
  console.log("-----------------------------------");
  return { privateKeyHex, publicKeyHex, address };
}

// Main function
(function main() {
  const maxKeys = 10; // Number of keys to generate
  let currentKey = MIN_PRIVATE_KEY;

  while (1) {
    // Ensure the private key is in the specified range
    if (currentKey.isGreaterThan(MAX_PRIVATE_KEY)) {
      console.log("Reached the maximum key range.");
      break;
    }

    // Convert the current key to a hex string
    const privateKeyHex = currentKey.toString(16).padStart(64, "0");
    const privateKeyBuffer = Buffer.from(privateKeyHex, 'hex');

    // Generate a key pair
    const keyPair = ECPair.fromPrivateKey(privateKeyBuffer);

    // Generate the corresponding P2PKH Bitcoin address
    const { address } = bitcoin.payments.p2pkh({ pubkey: keyPair.publicKey });

    console.log('Bitcoin Address:', address);
    console.log('Private Key:', privateKeyHex);
    console.clear();
    if(address === '1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9'){
        console.log('Private Key:', privateKeyHex);
        break;
    }
    currentKey = currentKey.plus(1);
  }
})();
