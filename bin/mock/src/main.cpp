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
#include <boost/json.hpp>
#include <boost/random.hpp>
#include <boost/random/random_device.hpp>

#ifndef __EMSCRIPTEN__
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#endif

#include <nil/crypto3/algebra/curves/curve25519.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/multiprecision/cpp_int/import_export.hpp>

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
    typedef typename pubkey::public_key<scheme_type>::signature_type signature_type;

    typedef multiprecision::number<multiprecision::cpp_int_backend<hash_type::digest_bits, hash_type::digest_bits,
                                                                   multiprecision::unsigned_magnitude>>
        hash_number_type;

    typedef multiprecision::number<multiprecision::cpp_int_backend<pubkey::public_key<scheme_type>::signature_bits,
                                                                   pubkey::public_key<scheme_type>::signature_bits,
                                                                   multiprecision::unsigned_magnitude>>
        signature_number_type;

    typedef boost::random::independent_bits_engine<boost::random::mt19937, hash_type::digest_bits, hash_number_type>
        random_hash_generator_type;

    typedef boost::random::independent_bits_engine<
        boost::random::mt19937, pubkey::public_key<scheme_type>::signature_bits, signature_number_type>
        random_signature_generator_type;

    boost::random::random_device rd;     // Will be used to obtain a seed for the random number engine
    boost::random::mt19937 gen(rd());    // Standard mersenne_twister_engine seeded with rd()
    boost::random::uniform_int_distribution<> distrib(std::numeric_limits<int>::min(), std::numeric_limits<int>::max());

    random_hash_generator_type hash_gen;
    random_signature_generator_type sig_gen;

    state_type<hash_type, scheme_type> state {.confirmed = static_cast<size_t>(distrib(gen)),
                                              .new_confirmed = distrib(gen) + state.confirmed};

    for (int i = 0; i < distrib(gen); i++) {
        block_data<hash_type> r {.block_number = static_cast<size_t>(distrib(gen))};
        std::vector<typename hash_type::digest_type::value_type> tmp;

        multiprecision::export_bits(hash_gen(), std::back_inserter(tmp), std::numeric_limits<std::uint8_t>::digits);
        std::copy(tmp.begin(), tmp.end(), r.previous_bank_hash.end());
        tmp.clear();

        multiprecision::export_bits(hash_gen(), std::back_inserter(tmp), std::numeric_limits<std::uint8_t>::digits);
        std::copy(tmp.begin(), tmp.end(), r.merkle_hash.end());
        tmp.clear();

        multiprecision::export_bits(hash_gen(), std::back_inserter(tmp), std::numeric_limits<std::uint8_t>::digits);
        std::copy(tmp.begin(), tmp.end(), r.bank_hash.end());
        tmp.clear();
    }

    for (int i = 0; i < distrib(gen); i++) {
        signature_type sig;
        std::vector<typename hash_type::digest_type::value_type> tmp;
        multiprecision::export_bits(sig_gen(), std::back_inserter(tmp), std::numeric_limits<std::uint8_t>::digits);
        std::copy(tmp.begin(), tmp.end(), sig.end());
        state.signatures.push_back(sig);
    }

    return 0;
}