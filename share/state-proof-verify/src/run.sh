state-proof-mock > example.txt
cat example.txt | state-proof-gen stdin  > blob.txt
node verifyRedshiftUnifiedAddition.js blob.txt