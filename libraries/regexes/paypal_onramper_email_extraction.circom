pragma circom 2.1.5;

include "@zk-email/zk-regex-circom/circuits/regex_helpers.circom";

// regex: <(s|p|a|n|=|\r|\n)+>[A-Za-z0-9_.=\r\n-]+@[A-Za-z0-9._=\r\n-]+<
template PaypalOnramperEmailExtraction(msg_bytes) {
	signal input msg[msg_bytes];
	signal output out;

	var num_bytes = msg_bytes+1;
	signal in[num_bytes];
	in[0]<==255;
	for (var i = 0; i < msg_bytes; i++) {
		in[i+1] <== msg[i];
	}

	component eq[23][num_bytes];
	component lt[4][num_bytes];
	component and[12][num_bytes];
	component multi_or[5][num_bytes];
	signal states[num_bytes+1][8];
	signal states_tmp[num_bytes+1][8];
	signal from_zero_enabled[num_bytes+1];
	from_zero_enabled[num_bytes] <== 0;
	component state_changed[num_bytes];

	for (var i = 1; i < 8; i++) {
		states[0][i] <== 0;
	}

	for (var i = 0; i < num_bytes; i++) {
		state_changed[i] = MultiOR(7);
		states[i][0] <== 1;
		eq[0][i] = IsEqual();
		eq[0][i].in[0] <== in[i];
		eq[0][i].in[1] <== 60;
		and[0][i] = AND();
		and[0][i].a <== states[i][0];
		and[0][i].b <== eq[0][i].out;
		states_tmp[i+1][1] <== 0;
		eq[1][i] = IsEqual();
		eq[1][i].in[0] <== in[i];
		eq[1][i].in[1] <== 10;
		eq[2][i] = IsEqual();
		eq[2][i].in[0] <== in[i];
		eq[2][i].in[1] <== 13;
		eq[3][i] = IsEqual();
		eq[3][i].in[0] <== in[i];
		eq[3][i].in[1] <== 61;
		eq[4][i] = IsEqual();
		eq[4][i].in[0] <== in[i];
		eq[4][i].in[1] <== 97;
		eq[5][i] = IsEqual();
		eq[5][i].in[0] <== in[i];
		eq[5][i].in[1] <== 110;
		eq[6][i] = IsEqual();
		eq[6][i].in[0] <== in[i];
		eq[6][i].in[1] <== 112;
		eq[7][i] = IsEqual();
		eq[7][i].in[0] <== in[i];
		eq[7][i].in[1] <== 115;
		and[1][i] = AND();
		and[1][i].a <== states[i][1];
		multi_or[0][i] = MultiOR(7);
		multi_or[0][i].in[0] <== eq[1][i].out;
		multi_or[0][i].in[1] <== eq[2][i].out;
		multi_or[0][i].in[2] <== eq[3][i].out;
		multi_or[0][i].in[3] <== eq[4][i].out;
		multi_or[0][i].in[4] <== eq[5][i].out;
		multi_or[0][i].in[5] <== eq[6][i].out;
		multi_or[0][i].in[6] <== eq[7][i].out;
		and[1][i].b <== multi_or[0][i].out;
		and[2][i] = AND();
		and[2][i].a <== states[i][2];
		and[2][i].b <== multi_or[0][i].out;
		multi_or[1][i] = MultiOR(2);
		multi_or[1][i].in[0] <== and[1][i].out;
		multi_or[1][i].in[1] <== and[2][i].out;
		states[i+1][2] <== multi_or[1][i].out;
		eq[8][i] = IsEqual();
		eq[8][i].in[0] <== in[i];
		eq[8][i].in[1] <== 62;
		and[3][i] = AND();
		and[3][i].a <== states[i][2];
		and[3][i].b <== eq[8][i].out;
		states[i+1][3] <== and[3][i].out;
		lt[0][i] = LessEqThan(8);
		lt[0][i].in[0] <== 65;
		lt[0][i].in[1] <== in[i];
		lt[1][i] = LessEqThan(8);
		lt[1][i].in[0] <== in[i];
		lt[1][i].in[1] <== 90;
		and[4][i] = AND();
		and[4][i].a <== lt[0][i].out;
		and[4][i].b <== lt[1][i].out;
		lt[2][i] = LessEqThan(8);
		lt[2][i].in[0] <== 97;
		lt[2][i].in[1] <== in[i];
		lt[3][i] = LessEqThan(8);
		lt[3][i].in[0] <== in[i];
		lt[3][i].in[1] <== 122;
		and[5][i] = AND();
		and[5][i].a <== lt[2][i].out;
		and[5][i].b <== lt[3][i].out;
		eq[9][i] = IsEqual();
		eq[9][i].in[0] <== in[i];
		eq[9][i].in[1] <== 45;
		eq[10][i] = IsEqual();
		eq[10][i].in[0] <== in[i];
		eq[10][i].in[1] <== 46;
		eq[11][i] = IsEqual();
		eq[11][i].in[0] <== in[i];
		eq[11][i].in[1] <== 48;
		eq[12][i] = IsEqual();
		eq[12][i].in[0] <== in[i];
		eq[12][i].in[1] <== 49;
		eq[13][i] = IsEqual();
		eq[13][i].in[0] <== in[i];
		eq[13][i].in[1] <== 50;
		eq[14][i] = IsEqual();
		eq[14][i].in[0] <== in[i];
		eq[14][i].in[1] <== 51;
		eq[15][i] = IsEqual();
		eq[15][i].in[0] <== in[i];
		eq[15][i].in[1] <== 52;
		eq[16][i] = IsEqual();
		eq[16][i].in[0] <== in[i];
		eq[16][i].in[1] <== 53;
		eq[17][i] = IsEqual();
		eq[17][i].in[0] <== in[i];
		eq[17][i].in[1] <== 54;
		eq[18][i] = IsEqual();
		eq[18][i].in[0] <== in[i];
		eq[18][i].in[1] <== 55;
		eq[19][i] = IsEqual();
		eq[19][i].in[0] <== in[i];
		eq[19][i].in[1] <== 56;
		eq[20][i] = IsEqual();
		eq[20][i].in[0] <== in[i];
		eq[20][i].in[1] <== 57;
		eq[21][i] = IsEqual();
		eq[21][i].in[0] <== in[i];
		eq[21][i].in[1] <== 95;
		and[6][i] = AND();
		and[6][i].a <== states[i][3];
		multi_or[2][i] = MultiOR(18);
		multi_or[2][i].in[0] <== and[4][i].out;
		multi_or[2][i].in[1] <== and[5][i].out;
		multi_or[2][i].in[2] <== eq[1][i].out;
		multi_or[2][i].in[3] <== eq[2][i].out;
		multi_or[2][i].in[4] <== eq[9][i].out;
		multi_or[2][i].in[5] <== eq[10][i].out;
		multi_or[2][i].in[6] <== eq[11][i].out;
		multi_or[2][i].in[7] <== eq[12][i].out;
		multi_or[2][i].in[8] <== eq[13][i].out;
		multi_or[2][i].in[9] <== eq[14][i].out;
		multi_or[2][i].in[10] <== eq[15][i].out;
		multi_or[2][i].in[11] <== eq[16][i].out;
		multi_or[2][i].in[12] <== eq[17][i].out;
		multi_or[2][i].in[13] <== eq[18][i].out;
		multi_or[2][i].in[14] <== eq[19][i].out;
		multi_or[2][i].in[15] <== eq[20][i].out;
		multi_or[2][i].in[16] <== eq[3][i].out;
		multi_or[2][i].in[17] <== eq[21][i].out;
		and[6][i].b <== multi_or[2][i].out;
		and[7][i] = AND();
		and[7][i].a <== states[i][4];
		and[7][i].b <== multi_or[2][i].out;
		multi_or[3][i] = MultiOR(2);
		multi_or[3][i].in[0] <== and[6][i].out;
		multi_or[3][i].in[1] <== and[7][i].out;
		states[i+1][4] <== multi_or[3][i].out;
		eq[22][i] = IsEqual();
		eq[22][i].in[0] <== in[i];
		eq[22][i].in[1] <== 64;
		and[8][i] = AND();
		and[8][i].a <== states[i][4];
		and[8][i].b <== eq[22][i].out;
		states[i+1][5] <== and[8][i].out;
		and[9][i] = AND();
		and[9][i].a <== states[i][5];
		and[9][i].b <== multi_or[2][i].out;
		and[10][i] = AND();
		and[10][i].a <== states[i][6];
		and[10][i].b <== multi_or[2][i].out;
		multi_or[4][i] = MultiOR(2);
		multi_or[4][i].in[0] <== and[9][i].out;
		multi_or[4][i].in[1] <== and[10][i].out;
		states[i+1][6] <== multi_or[4][i].out;
		and[11][i] = AND();
		and[11][i].a <== states[i][6];
		and[11][i].b <== eq[0][i].out;
		states[i+1][7] <== and[11][i].out;
		from_zero_enabled[i] <== MultiNOR(7)([states_tmp[i+1][1], states[i+1][2], states[i+1][3], states[i+1][4], states[i+1][5], states[i+1][6], states[i+1][7]]);
		states[i+1][1] <== MultiOR(2)([states_tmp[i+1][1], from_zero_enabled[i] * and[0][i].out]);
		state_changed[i].in[0] <== states[i+1][1];
		state_changed[i].in[1] <== states[i+1][2];
		state_changed[i].in[2] <== states[i+1][3];
		state_changed[i].in[3] <== states[i+1][4];
		state_changed[i].in[4] <== states[i+1][5];
		state_changed[i].in[5] <== states[i+1][6];
		state_changed[i].in[6] <== states[i+1][7];
	}

	component final_state_result = MultiOR(num_bytes+1);
	for (var i = 0; i <= num_bytes; i++) {
		final_state_result.in[i] <== states[i][7];
	}
	out <== final_state_result.out;
	signal is_consecutive[msg_bytes+1][3];
	is_consecutive[msg_bytes][2] <== 1;
	for (var i = 0; i < msg_bytes; i++) {
		is_consecutive[msg_bytes-1-i][0] <== states[num_bytes-i][7] * (1 - is_consecutive[msg_bytes-i][2]) + is_consecutive[msg_bytes-i][2];
		is_consecutive[msg_bytes-1-i][1] <== state_changed[msg_bytes-i].out * is_consecutive[msg_bytes-1-i][0];
		is_consecutive[msg_bytes-1-i][2] <== ORAnd()([(1 - from_zero_enabled[msg_bytes-i+1]), states[num_bytes-i][7], is_consecutive[msg_bytes-1-i][1]]);
	}
	// substrings calculated: [{(3, 4), (4, 4), (4, 5), (5, 6), (6, 6)}]
	signal is_substr0[msg_bytes];
	signal is_reveal0[msg_bytes];
	signal output reveal0[msg_bytes];
	for (var i = 0; i < msg_bytes; i++) {
		 // the 0-th substring transitions: [(3, 4), (4, 4), (4, 5), (5, 6), (6, 6)]
		is_substr0[i] <== MultiOR(5)([states[i+1][3] * states[i+2][4], states[i+1][4] * states[i+2][4], states[i+1][4] * states[i+2][5], states[i+1][5] * states[i+2][6], states[i+1][6] * states[i+2][6]]);
		is_reveal0[i] <== is_substr0[i] * is_consecutive[i][2];
		reveal0[i] <== in[i+1] * is_reveal0[i];
	}
}