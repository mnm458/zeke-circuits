pragma circom 2.1.5;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";

template Numberify(bytes_len) {
    signal input in[bytes_len];
    signal output out;
    signal sum[bytes_len + 1];
    signal exp[bytes_len + 1];
    
    component _and[bytes_len];

    exp[bytes_len] <== 1;
    sum[bytes_len] <== 0;

    for (var i = bytes_len - 1; i >= 0; i--) {

        _and[i] = MultiAND(3);
        _and[i].in[0] <== GreaterEqThan(8)([in[i], 48]);
        _and[i].in[1] <== LessEqThan(8)([in[i], 57]);
        _and[i].in[2] <== exp[i + 1];
        // if any other digit other than [48, 57] both inclusive
        // then e2 does not get upgraded
        sum[i] <== sum[i+1] + ((in[i] - 48) * _and[i].out);
        exp[i] <== exp[i + 1] + (9  * _and[i].out);
    }
    out <== sum[0];

}