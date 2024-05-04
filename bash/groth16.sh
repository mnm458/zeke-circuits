#!/bin/bash

# Define the source and destination directories
source_directory="circuits"
destination_directory="groth16"
input_directory="inputs"

# export NODE_OPTIONS=--max_old_space_size=200000

# Check if the destination directory exists, if not, create it
if [ ! -d "$destination_directory" ]; then
    mkdir -p "$destination_directory"
fi

run_parallel_loop() {

    directory="$destination_directory/$filename"

    if [[ $filename != _* ]]; then

        filename="$1"
        mkdir -p "$destination_directory/$filename"
        
        circom "$source_directory/$filename".circom --r1cs --c --wasm --sym -o "$destination_directory/$filename" -l ./node_modules

        # NODE_OPTIONS='--max-old-space-size=420000' npx snarkjs r1cs export json "$destination_directory/$filename/$filename".r1cs "$destination_directory/$filename/$filename".r1cs.json
        NODE_OPTIONS='--max-old-space-size=420000' npx snarkjs groth16 setup "$destination_directory/$filename/$filename".r1cs "$destination_directory"/common/ptau_25.ptau "$destination_directory/$filename"/circuit_0.zkey -v 
        NODE_OPTIONS='--max-old-space-size=420000' npx snarkjs zkey contribute "$destination_directory/$filename"/circuit_0.zkey "$destination_directory/$filename"/circuit.zkey -v -e="$(head -c 125 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9!@#$%^&*()_-')" -v
        
        # snarkjs zkey verify "$destination_directory/$filename".r1cs "$destination_directory"/common/ptau_18.ptau "$destination_directory/$filename"/circuit_1.zkey

        NODE_OPTIONS='--max-old-space-size=420000' npx snarkjs zkey export verificationkey "$destination_directory/$filename"/circuit.zkey "$destination_directory/$filename"/vkey.json
        NODE_OPTIONS='--max-old-space-size=420000' npx snarkjs zkey export solidityverifier "$destination_directory/$filename"/circuit.zkey "$destination_directory/$filename"/verifier.sol

        if [[ -f "$input_directory/$filename".json  ]]; then
            # node "$destination_directory/$filename/$filename"_js/generate_witness.js "$destination_directory/$filename/$filename"_js/"$filename".wasm "$input_directory/$filename".json "$destination_directory/$filename"/witness.wtns
            ./bin/prover "$destination_directory/$filename"/circuit.zkey "$destination_directory/$filename"/witness.wtns "$destination_directory/$filename"/proof.json "$destination_directory/$filename"/public.json
        fi
    fi

}

# Loop through each .circom file in the source directory
for circuit_file in "$source_directory"/*.circom; do
    # Extract the filename without extension
    filename=$(basename "$circuit_file" .circom)
    
    run_parallel_loop "$filename" &
done

wait

echo "Build completed."

