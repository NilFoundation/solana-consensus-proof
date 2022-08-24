import requests
import pprint
from typing import List
import json
import copy
import random

url = "https://api.devnet.solana.com"

last_block = 0


class VoteState:
    pubkey = ""
    weight = 1
    signature = ""

    def __init__(self, pubkey, signature="", weight=1):
        self.pubkey = pubkey
        self.signature = signature
        self.weight = weight

    def json(self):
        return {"pubkey": self.pubkey, "weight": self.weight, "signature": self.signature}


class BlockData:
    block_number: int = 0
    bank_hash: str = ""
    previous_bank_hash: str = ""
    timestamp = 0
    votes: List[VoteState] = []

    def __init__(self, block_number, bank_hash, previous_bank_hash, timestamp, pubkeys):
        self.block_number = block_number
        self.bank_hash = bank_hash
        self.previous_bank_hash = previous_bank_hash
        self.timestamp = timestamp
        self.votes = []
        for cur_pubkey in pubkeys:
            self.votes.append(VoteState(cur_pubkey))

    def json(self):
        return {"block_number": self.block_number, "bank_hash": self.bank_hash,
                "previous_bank_hash": self.previous_bank_hash, "timestamp": self.timestamp,
                "votes": [i.json() for i in self.votes]}


class StateType:
    confirmed: int = 0
    new_confirmed: int = 0

    repl_data: List[BlockData] = []

    def __init__(self, previous_confirmed, confirmed, blocks):
        self.confirmed = previous_confirmed
        self.new_confirmed = confirmed
        self.repl_data = blocks[:]

    def json(self):
        return {"confirmed": self.confirmed, "new_confirmed": self.new_confirmed,
                "repl_data": [i.json() for i in self.repl_data]}


def get_previous_slot(slot):
    i = 40
    while True:
        res = requests.post(url=url,
                            json={"jsonrpc": "2.0", "id": 1, "method": "getBlocksWithLimit",
                                  "params": [slot - 1 - i, 40]})
        if len(res.json()['result']) == 2:
            return res.json()['result'][0]
        i += 1


def get_blocks_range(slot, range=5):
    res = requests.post(url=url,
                        json={"jsonrpc": "2.0", "id": 1, "method": "getBlocks", "params": [slot - range, slot]})
    return res.json()['result']


def get_last_slot():
    res = requests.post(url=url, json={"jsonrpc": "2.0", "id": 1, "method": "getSlot"})
    return res.json()['result']


def get_block(slot):
    res = requests.post(url=url, json={"jsonrpc": "2.0", "id": 1, "method": "getBlock", "params": [slot,
                                                                                                   {"encoding": "json",
                                                                                                    "transactionDetails": "none",
                                                                                                    "rewards": True}]})
    res = res.json()['result']
    block_number = slot
    bank_hash = res['blockhash']
    previous_bank_hash = res['previousBlockhash']
    pubkeys = [i['pubkey'] for i in res['rewards']]
    type_r = [i['rewardType'] for i in res['rewards']]
    timestamp = 0 if res['blockTime'] is None else res['blockTime']
    return block_number, bank_hash, previous_bank_hash, timestamp, pubkeys


previous_confirmed = last_block
last_block = get_last_slot()
blocks_to_proof = get_blocks_range(last_block, range=150)
blocks = []
print("Start to get blocks")
for i in blocks_to_proof:
    print("Block get: %d" % i)
    block_number, bank_hash, previous_bank_hash, timestamp, pubkeys = get_block(i)
    x = BlockData(block_number, bank_hash, previous_bank_hash, timestamp, pubkeys)
    blocks.append(x)

state = StateType(previous_confirmed, last_block, blocks)

with open('data.json', 'w') as f:
    print(json.dumps(state.json(), indent=2), file=f)
