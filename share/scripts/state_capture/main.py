import time
import sys
import block_data
import validators_exporter
import json


state, confirmed_block = block_data.get_data(0)

with open('data.json', 'w') as f:
    print(json.dumps(state.json(), indent=2), file=f)

with open('validators_count.txt', 'w') as f:
    print(str(validators_exporter.get_validators_count()), file=f)