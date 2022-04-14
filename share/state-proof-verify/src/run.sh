#!/bin/sh
if [ -f $1 ]; then
  rm -f time.log
  echo "Name Time_execution" > time.log
  state-proof-mock | state-proof-gen | node verifyRedshiftUnifiedAddition.js $1
  cat time.log | column -t
else
    echo "Secret on path $1 does not exist."
fi
