#!/bin/bash

python3 /home/share/scripts/state_capture/main.py
cat data.json > tmp.txt
cat validators_count.txt > tmp.txt
/home/build/bin/state-mock/state-mock -i data.json --validators `cat validators_count.txt`
