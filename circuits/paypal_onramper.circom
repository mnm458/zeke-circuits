pragma circom 2.1.5;

include "circomlib/circuits/poseidon.circom";
include "../libraries/utils/ceil.circom";
include "../libraries/utils/email_nullifier.circom";
include "../libraries/utils/hash_sign_gen_rand.circom";

include "../libraries/utils/email-verifier.circom";
include "../libraries/utils/extract.circom";
include "../libraries/utils/merkle.circom";
include "../libraries/utils/numberify.circom";

include "../libraries/regexes/paypal_actor_email.circom";
include "../libraries/regexes/paypal_from_email.circom";
include "../libraries/regexes/paypal_offramper_email_extraction.circom";
include "../libraries/regexes/paypal_onramper_email_extraction.circom";
include "../libraries/regexes/paypal_send_amount.circom";
include "../libraries/regexes/paypal_timestamp.circom";

// 768, 6144, 121, 17, 7, 80, 20, 9
template PaypalEmailProofOnramper(max_header_bytes, max_body_bytes, n, k, pack_size, email_extract_size, email_pack_size, levels) {
    assert(n * k > 1024); // constraints for 1024 bit RSA

    // Rounded to the nearest multiple of pack_size for extra room in case of change of constants
    var max_email_amount_len = 25; // Allowing max 4 fig amount + one decimal point + 2 decimal places. e.g. $2,500.00
    var max_email_timestamp_len = 40; // 10 digits till year 2286
    // 21 digits does not include the 3 chars `=\r\n` extracted from regex. These 3 chars will be removed during shift and pack
    // Current paypal IDs are 19 digits, but we allow for 21 digits to be future proof
    // var max_offramper_len = ceil(21, pack_size);

    signal input in_padded[max_header_bytes]; // prehashed email data, includes up to 512 + 64? bytes of padding pre SHA256, and padded with lots of 0s at end after the length
    signal input modulus[k]; // rsa pubkey, verified with smart contract + DNSSEC proof. split up into k parts of n bits each.
    signal input signature[k]; // rsa signature. split up into k parts of n bits each.
    signal input in_len_padded_bytes; // length of in email data including the padding, which will inform the sha256 block length

    // Base 64 body hash variables
    signal input body_hash_idx;
    // The precomputed_sha value is the Merkle-Damgard state of our SHA hash uptil our first regex match which allows us to save SHA constraints by only hashing the relevant part of the body
    signal input precomputed_sha[32];
    // Suffix of the body after precomputed SHA
    signal input in_body_padded[max_body_bytes];
    // Length of the body after precomputed SHA
    signal input in_body_len_padded_bytes;

    signal output modulus_hash;

    // DKIM VERIFICATION
    component EV = EmailVerifierPaypal(max_header_bytes, max_body_bytes, n, k, 0);
    EV.in_padded <== in_padded;
    EV.pubkey <== modulus;
    EV.signature <== signature;
    EV.in_len_padded_bytes <== in_len_padded_bytes;
    EV.body_hash_idx <== body_hash_idx;
    EV.precomputed_sha <== precomputed_sha;
    EV.in_body_padded <== in_body_padded;
    EV.in_body_len_padded_bytes <== in_body_len_padded_bytes;
    signal header_hash[256] <== EV.sha;

    modulus_hash <== EV.pubkey_hash;
    signal output email_hash_poseidon <== EV.email_hash_poseidon;
    signal output post_compute_hash <== EV.post_compute_hash;

    // FROM HEADER REGEX
    // This extracts the from email, and the precise regex format can be viewed in the README
    assert(email_extract_size < max_header_bytes);

    signal input email_from_idx;

    signal reveal_email_from[email_extract_size] <== VarShiftLeft(max_header_bytes, email_extract_size)(in_padded, email_from_idx);
    signal (from_regex_out, from_regex_reveal[email_extract_size]) <== PaypalFromEmailExtraction(email_extract_size)(reveal_email_from);
    signal output from_regex_reveal_poseidon <== EmailHasher(email_extract_size, email_pack_size)(from_regex_reveal);
    from_regex_out === 1;

    // paypal SEND AMOUNT REGEX
    assert(max_email_amount_len < max_header_bytes);

    signal input paypal_amount_idx;

    signal reveal_email_amount[max_email_amount_len] <== VarShiftLeft(max_body_bytes, max_email_amount_len)(in_body_padded, paypal_amount_idx);
    signal (amount_regex_out, amount_regex_reveal[max_email_amount_len]) <== PaypalAmountRegex(max_email_amount_len)(reveal_email_amount);
    amount_regex_out === 1;
    signal output actual_amount <== Numberify(max_email_amount_len)(amount_regex_reveal);

    // TIMESTAMP REGEX
    assert(max_email_timestamp_len < max_header_bytes);

    signal input email_timestamp_idx;

    signal reveal_email_timestamp_packed[max_email_timestamp_len] <== VarShiftLeft(max_header_bytes, max_email_timestamp_len)(in_padded, email_timestamp_idx);
    signal (timestamp_regex_out, timestamp_regex_reveal[max_email_timestamp_len]) <== PaypalTimestampExtraction(max_email_timestamp_len)(reveal_email_timestamp_packed);
    timestamp_regex_out === 1;

    signal output actual_timestamp <== Numberify(max_email_timestamp_len)(timestamp_regex_reveal);

    // email extraction
    signal input paypal_offramper_id_idx;
    signal input paypal_onramper_id_idx;

    // extract the onramper id from the email
    signal offramper_email[email_extract_size] <== VarShiftLeft(max_body_bytes, email_extract_size)(in_body_padded, paypal_offramper_id_idx);
    signal (offramper_regex_out, offramper_regex_reveal[email_extract_size]) <== PaypalOfframperEmailExtraction(email_extract_size)(offramper_email);
    onramper_regex_out === 1;

    // extract the TO email for offramper id
    signal onramper_email[email_extract_size] <== VarShiftLeft(max_header_bytes, email_extract_size)(in_padded, paypal_onramper_id_idx);
    signal (onramper_regex_out, onramper_regex_reveal[email_extract_size]) <== PaypalActorEmailExtraction(email_extract_size)(onramper_email);
    offramper_regex_out === 1;

    // HASH OFFRAMPER EMAIL
    // pack for each email, make an integer number leaf from Poseidon hash
    // then generate merkle root and set that as hashed email output
    signal input pathElementsOfframper[levels];
    signal input pathIndicesOfframper[levels];
    signal output packed_offramper_id_hashed <== MerkleTreeChecker(levels, email_extract_size, email_pack_size)(offramper_regex_reveal, pathElementsOfframper, pathIndicesOfframper);

    
    // HASH ONRAMPER EMAIL
    // pack for each email, make an integer number leaf from Poseidon hash
    // then generate merkle root and set that as hashed email output
    signal input pathElementsOnramper[levels];
    signal input pathIndicesOnramper[levels];
    signal output packed_onramper_id_hashed <== MerkleTreeChecker(levels, email_extract_size, email_pack_size)(onramper_regex_reveal, pathElementsOnramper, pathIndicesOnramper);


    // Later TODO: P2P PAYMENT CHECK REGEX
    // signal paypal_p2p_check_regex_out;
    // paypal_p2p_check_regex_out <== paypalP2PCheckRegex(max_body_bytes)(in_body_padded);
    // paypal_p2p_check_regex_out === 0;

    // NULLIFIER
    signal cm_rand <== HashSignGenRand(n, k)(signature);
    signal output email_nullifier <== EmailNullifier()(header_hash, cm_rand);

    // The following signals do not take part in any computation, but tie the proof to a specific intent_hash & claim_id to prevent replay attacks and frontrunning.
    // https://geometry.xyz/notebook/groth16-malleability
    signal input intent_hash;
    signal intent_hash_squared <== intent_hash * intent_hash;

    // TOTAL CONSTRAINTS: 8160368
}

// Args:
// * max_header_bytes = 768 is the max number of bytes in the header
// * max_body_bytes = 6272 is the max number of bytes in the body after precomputed slice (Need to leave room for >280 char custom message)
// * n = 121 is the number of bits in each chunk of the modulus (RSA parameter)
// * k = 17 is the number of chunks in the modulus (RSA parameter)
// * pack_size = 7 is the number of bytes that can fit into a 255ish bit signal (can increase later)
component main { public [ intent_hash ] } = PaypalEmailProofOnramper(768, 6144, 121, 17, 7, 80, 20, 9);
