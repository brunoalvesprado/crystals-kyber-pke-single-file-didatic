# Crystals-Kyber TypeScript (Node.js)

A Didactic direct approach implementation of Crystals-Kyber in TypeScript for Node.js, a post-quantum cryptography algorithm that is part of the NIST standardization process, standardized on FIPS 203 as ML_KEM.

## Features

- Pure TypeScript implementation
- Support for Kyber512, Kyber768, and Kyber1024 variants
- Key generation, encryption, and decryption
- For didatic purposes and better reading access, all coding is consolidated in a single file.

## Requirements

- Node.js v16+
- npm or yarn

## Installation

Clone this repository and install dependencies:

```sh
git clone https://github.com/brunoalvesprado/crystals-kyber-pke-single-file-didatic.git
cd crystals-kyber-pke-single-file-didatic
npm install
```

## Build

```sh
npm run build
```

or

```sh
npx tsc
```

## Start

```sh
npm start
```

## Example

### Key Generation

```ts
// Generate Alice and Bob keys.
let {pKey:Alice_pKey, sKey:Alice_sKey} = crystalsKyber_generateKeys();
let {pKey:Bob_pKey, sKey:Bob_sKey} = crystalsKyber_generateKeys();
```

### Encryption and Decryption

```ts
// Alice -> Bob
let msgAlice = "Hey Bob, Alice here, how are you?";

let ctMsgAlice = crystalsKyber_encryptMessage(msgAlice, Bob_pKey);
let decryptedMsgAlice = crystalsKyber_decryptMessage(ctMsgAlice, Bob_sKey);

// Bob -> Alice
let msgBob = "Yes Alice, this is Bob, I'm fine, how are you too?";

let ctMsgBob = crystalsKyber_encryptMessage(msgBob, Alice_pKey);
let decryptedMsgBob = crystalsKyber_decryptMessage(ctMsgBob, Alice_sKey);
```

## License

GNU General Public License (GPL) v3
