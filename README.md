# zeke-circuits

## DKIM Verification:

- The circuits includes an EmailVerifierPaypal component that verifies the DKIM (DomainKeys Identified Mail) signature of the email.
- It takes the email header data, public key (modulus), signature, and body data as inputs.
- The DKIM verification ensures that the email is authentic and hasn't been tampered with.
- The circuit outputs the header hash, email hash (using Poseidon hash), and post-compute hash.

## Regular Expression (Regex) Extractions:

- The circuit uses several regex components to extract specific information from the email header and body.
- It extracts the "From" email address, PayPal send amount, and timestamp using regex patterns.
- The extracted data is then processed and converted into signals for further use.

## Email Extraction:

- The circuit extracts the offramper and onramper email IDs from the email body and header, respectively.
- It uses regex components (PaypalOfframperEmailExtraction and PaypalActorEmailExtraction) to match and extract the relevant email IDs.

## Merkle Tree Hashing:

- The extracted offramper and onramper email IDs are hashed using a Merkle tree.
- The email IDs are first packed into fixed-size chunks (email_pack_size) and then hashed using the Poseidon hash function to create leaf nodes.
- The Merkle tree is constructed using the MerkleTreeChecker component, which takes the leaf nodes, path elements, and path indices as inputs.
- The circuit outputs the Merkle root hash for both the offramper and onramper email IDs.

## Nullifier Generation:

The circuit generates a unique nullifier for the email using the EmailNullifier component.
It takes the header hash and a random value (derived from the signature) as inputs and outputs the nullifier.
The nullifier serves as a unique identifier for the email and prevents double-spending or replay attacks.

## Intent Hash:

The circuit includes an intent hash input, which is used to tie the proof to a specific transaction intent.
