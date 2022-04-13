/Users/Zerg/Projects/evm-solana-verification/cmake-build-debug/bin/state-mock/state-proof-mock > example.txt
cat example.txt | /Users/Zerg/Projects/evm-solana-verification/cmake-build-debug/bin/state-proof-gen/state-proof-gen stdin  > blob.txt
node verifyRedshiftUnifiedAddition.js blob.txt

