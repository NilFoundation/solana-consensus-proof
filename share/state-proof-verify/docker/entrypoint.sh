#!/bin/bash
#while read line
#do
#  echo "$line"
#done < "${1:-/dev/stdin}"
cat "${1:-/dev/stdin}" > /.secret
export LD_LIBRARY_PATH=/usr/local/lib/
cd /home/app/share/state-proof-verify/src/
./run.sh /.secret