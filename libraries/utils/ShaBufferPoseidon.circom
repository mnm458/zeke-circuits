pragma circom 2.1.5;

include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/email-verifier.circom";
include "circomlib/circuits/bitify.circom";


template Numberifier(n) {
    signal input in[n];
    signal output out;
    var lc1=0;

    var e2 = 1;
    for (var i = 0; i<n; i++) {
        lc1 += in[n-i-1] * e2;
        e2 = e2 + e2;
    }

    lc1 ==> out;
}

template ShaBufferPoseidon(){

    signal input inputs[32];

    component hasher = Poseidon(8);
    for(var i = 0; i < 8; i++){
        hasher.inputs[i] <== (inputs[4*i + 0] * 16777216) + (inputs[4*i + 1] * 65536) + (inputs[4*i + 2] * 256) + (inputs[4*i + 3]);
    }

    signal output out <== hasher.out;

}


template MerkleDamgardVerifier(max_num_bytes){

    signal input in[max_num_bytes];
    signal input length;
    signal input pre_hash[32];

    component hasher = Sha256BytesPartial(max_num_bytes);
    hasher.in_padded <== in;
    hasher.in_len_padded_bytes <== length;
    hasher.pre_hash <== pre_hash;

    signal _out[256] <== hasher.out;
    signal out[32];

    component numberifiers[32];

    for(var i = 0; i < 32; i++){
        numberifiers[i] = Numberifier(8);
        for(var j = 0; j < 8; j++){
            numberifiers[i].in[j] <== _out[(i * 8) + j];
        }
        out[i] <== numberifiers[i].out;
    }

    signal output pre_compute_hash <== ShaBufferPoseidon()(pre_hash);
    signal output post_compute_hash <== ShaBufferPoseidon()(out);

}

/* 
    pre_hash values that would mock exact Sah256 full hash:
    [
        106, 9,   230, 103,
        187, 103, 174, 133,
        60,  110, 243, 114,
        165, 79,  245, 58,
        81,  14,  82,  127,
        155, 5,   104, 140,
        31,  131, 217, 171,
        91,  224, 205, 25
    ]
 */
