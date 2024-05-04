pragma circom 2.1.5;

/*This circuit template checks that c is the multiplication of a and b.*/  
include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/helpers/extract.circom";

// Computes Poseidon([left, right])
template HashLeftRight() {
    signal input left;
    signal input right;
    signal output hash;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== left;
    hasher.inputs[1] <== right;
    hash <== hasher.out;
}

// s indicates whether input will be switched or not
// if s == 0 returns [in[0], in[1]]
// if s == 1 returns [in[1], in[0]]
template DualMux() {
    signal input in[2];
    signal input s;
    signal output out[2];

    s * (1 - s) === 0;
    out[0] <== (in[1] - in[0])*s + in[0];
    out[1] <== (in[0] - in[1])*s + in[1];
}

template EmailHasher(max_email_bytes, pack_size) {
    signal input email[max_email_bytes];

    // compact the email
    var max_substr_len_packed = ((max_email_bytes - 1) \ pack_size + 1);
    component packer = PackBytes(max_email_bytes, max_substr_len_packed, pack_size);
    packer.in <== email;

    signal output email_hash <== Poseidon(max_substr_len_packed)(packer.out);
}

// Verifies that merkle proof is correct for given merkle root and a leaf
// pathIndices input is an array of 0/1 selectors telling whether given pathElement is on the left or right side of merkle path
template MerkleTreeChecker(levels, max_email_bytes, pack_size) {
    // compact this email bytes
    signal input email[max_email_bytes];

    // the user will need to fetch un-nullified pathElements by themselves
    signal input pathElements[levels];
    signal input pathIndices[levels];
    
    // this root must strictly be an existing root
    signal output root;

    component selectors[levels];
    component hashers[levels];

    // compact the email
    signal leaf <== EmailHasher(max_email_bytes, pack_size)(email);
    
    for (var i = 0; i < levels; i++) {
        selectors[i] = DualMux();
        selectors[i].in[0] <== i == 0 ? leaf : hashers[i - 1].hash;
        selectors[i].in[1] <== pathElements[i];
        selectors[i].s <== pathIndices[i];

        hashers[i] = HashLeftRight();
        hashers[i].left <== selectors[i].out[0];
        hashers[i].right <== selectors[i].out[1];
    }

    root <== hashers[levels - 1].hash;
    /* Automatically becomes output */
    /* Created just for the smart contract's help */
    /* Becomes the ID of the created token */
}

/* Characteristics must strictly conform to pre-decided guidelines, to prevent any leakage of private information */
/* Checks must be added to smart contract */
/* Public inputs are added at the end of public variables */

/* Step 4:(User side) Create this during payout claiming */
// component main = MerkleTreeChecker(7, 76, 20);


/*  Understanding:
    1.  If nullifier is used, then no payout
    2.  The root must be an existing one, preferably different from the root made in interaction phase
*/
