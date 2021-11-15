//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------//

#include <iostream>

#include <boost/circular_buffer.hpp>
#include <boost/optional.hpp>

#ifndef __EMSCRIPTEN__
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#endif

#include <nil/crypto3/algebra/curves/curve25519.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/eddsa.hpp>

#include <nil/marshalling/status_type.hpp>

using namespace nil::crypto3;

struct lockout {
    std::uint64_t slot;
    std::uint32_t confirmation_count;
};

struct block_timestamp {
    std::uint64_t slot;
    std::time_t timestamp;
};

template<typename SignatureSchemeType>
struct vote_state {
    typedef SignatureSchemeType scheme_type;
    typedef pubkey::private_key<scheme_type> private_key_type;
    typedef pubkey::public_key<scheme_type> public_key_type;

    /// the node that votes in this account
    public_key_type node_pubkey;

    /// the signer for vote transactions
    public_key_type authorized_voter;

    /// the signer for withdrawals
    public_key_type authorized_withdrawer;

    /// percentage (0-100) that represents what part of a rewards
    ///  payout should be given to this VoteAccount
    std::uint8_t commission;

    /// when the authorized voter was set/initialized
    std::uint64_t authorized_voter_epoch;

    /// history of prior authorized voters and the epoch ranges for which
    ///  they were set
    boost::circular_buffer<std::tuple<public_key_type, std::uint64_t, std::uint64_t, std::uint64_t>> prior_voters;

    std::deque<lockout> votes;

    boost::optional<std::uint64_t> root_slot;

    /// history of how many credits earned by the end of each epoch
    ///  each tuple is (Epoch, credits, prev_credits)
    std::vector<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>> epoch_credits;

    /// most recent timestamp submitted with a vote
    block_timestamp last_timestamp;
};

template<typename Hash>
struct block_data {
    typedef typename Hash::digest_type digest_type;

    std::size_t block_number;
    digest_type bank_hash;
    digest_type merkle_hash;
    digest_type previous_bank_hash;
    //    std::vector<vote_state> votes; </// Not implemented yet. Requires Solana replication protocol changes.
};

template<typename Hash, typename SignatureSchemeType>
struct state_type {
    typedef Hash hash_type;
    typedef SignatureSchemeType signature_scheme_type;
    typedef typename pubkey::public_key<signature_scheme_type>::signature_type signature_type;

    std::size_t confirmed;
    std::size_t new_confirmed;
    std::vector<block_data<hash_type>> repl_data;
    std::vector<signature_type> signatures;
};

int main(int argc, char *argv[]) {

    typedef hashes::sha2<256> hash_type;
    typedef algebra::curves::curve25519 curve_type;
    typedef typename curve_type::template g1_type<> group_type;
    typedef pubkey::eddsa<group_type, pubkey::EddsaVariant::basic, void> scheme_type;

    state_type<hash_type, scheme_type> state;

    return 0;
}