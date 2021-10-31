# In-EVM Solana "Light Client" State Verification.

This repository contains In-EVM Solana Light-Client State verification project. In particular:

1. Solana "light-client" mock data generator according to the description in here: https://docs.solana.com/proposals/simple-payment-and-state-verification#light-clients.
2. Solana "light-client" state proof submission protocol and circuit description.
3. State proof generator (`prove`)
4. In-EVM state proof verificator.

## Mock Data Generator

Auxiliary proof generator is implemented in C++ and uses =nil; Crypto3 C++ Cryptography Suite
(https://github.com/nilfoundation/crypto3) for cryptographic primitives definition.

### Dependencies

Libraries requirements are as follows:
* Boost (https://boost.org) (>= 1.76)

Compiler/environment requirements are as follows:
* CMake (https://cmake.org) (>= 3.13)
* GCC (>= 10.3) / Clang (>= 9.0.0) / AppleClang (>= 11.0.0)

### Building

`mkdir build && cd build && cmake .. && make mock`

### Usage

## State Circuit Description & Submission Protocol

Project documentation is available at https://solana.nil.foundation/projects/verification

## Light-Client State Proof Generator

Light-client state proof generator is a UNIX-style application taking Solana's light-client state data as an input and producing the proof as an output. 

It is implemented in C++ and uses =nil; Crypto3 C++ Cryptography Suite (https://github.com/nilfoundation/crypto3) for cryptographic primitives definition.

### Dependencies

Libraries requirements are as follows:
* Boost (https://boost.org) (>= 1.76)

Compiler/environment requirements are as follows:
* CMake (https://cmake.org) (>= 3.13)
* GCC (>= 10.3) / Clang (>= 9.0.0) / AppleClang (>= 11.0.0)

### Building

`mkdir build && cd build && cmake .. && make prove`

### Usage

## Community

Issue reports are preferred to be done with Github Issues in here: https://github.com/nilfoundation/evm-solana-verification.git.

Usage and development questions a preferred to be asked in a Telegram chat: https:/t.me/nilcrypto3