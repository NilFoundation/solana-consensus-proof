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
#include <chrono>

#include <boost/circular_buffer.hpp>
#include <boost/optional.hpp>
#include <boost/json/src.hpp>
#include <boost/random.hpp>
#include <boost/random/random_device.hpp>

#ifndef __EMSCRIPTEN__
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#endif

#include <nil/crypto3/algebra/curves/curve25519.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/eddsa.hpp>

#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/marshalling/status_type.hpp>

#include <nil/crypto3/marshalling/multiprecision/types/integral.hpp>

using namespace nil::crypto3;
using namespace nil::marshalling;

template<typename Hash>
struct vote_state {
    typedef Hash hash_type;
    typedef typename Hash::digest_type digest_type;

    /// A stack of votes starting with the oldest vote
    std::vector<std::uint64_t> slots;
    /// signature of the bank's state at the last slot
    digest_type hash;
    /// processing timestamp of last slot
    std::uint32_t timestamp;
    /// vote weight
    std::size_t weight;
};

template<typename Hash>
struct block_data {
    typedef Hash hash_type;
    typedef typename Hash::digest_type digest_type;

    std::size_t block_number;
    digest_type bank_hash;
    digest_type merkle_hash;
    digest_type previous_bank_hash;
    std::vector<vote_state<Hash>> votes;
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

template<typename Hash>
void tag_invoke(boost::json::value_from_tag, boost::json::value &jv, block_data<Hash> const &c) {
    jv = {{"block_number", c.block_number},
          {"bank_hash", std::to_string(c.bank_hash)},
          {"merkle_hash", std::to_string(c.merkle_hash)},
          {"previous_bank_hash", std::to_string(c.previous_bank_hash)},
          {"votes", c.votes}};
}

template<typename Hash>
void tag_invoke(boost::json::value_from_tag, boost::json::value &jv, vote_state<Hash> const &c) {
    jv = {{"slots", c.slots}, {"hash", std::to_string(c.hash)}, {"timestamp", c.timestamp}, {"weight", c.weight}};
}

void pretty_print(std::ostream &os, boost::json::value const &jv, std::string *indent = nullptr) {
    std::string indent_;
    if (!indent)
        indent = &indent_;
    switch (jv.kind()) {
        case boost::json::kind::object: {
            os << "{\n";
            indent->append(4, ' ');
            auto const &obj = jv.get_object();
            if (!obj.empty()) {
                auto it = obj.begin();
                for (;;) {
                    os << *indent << boost::json::serialize(it->key()) << " : ";
                    pretty_print(os, it->value(), indent);
                    if (++it == obj.end())
                        break;
                    os << ",\n";
                }
            }
            os << "\n";
            indent->resize(indent->size() - 4);
            os << *indent << "}";
            break;
        }

        case boost::json::kind::array: {
            os << "[\n";
            indent->append(4, ' ');
            auto const &arr = jv.get_array();
            if (!arr.empty()) {
                auto it = arr.begin();
                for (;;) {
                    os << *indent;
                    pretty_print(os, *it, indent);
                    if (++it == arr.end())
                        break;
                    os << ",\n";
                }
            }
            os << "\n";
            indent->resize(indent->size() - 4);
            os << *indent << "]";
            break;
        }

        case boost::json::kind::string: {
            os << boost::json::serialize(jv.get_string());
            break;
        }

        case boost::json::kind::uint64:
            os << jv.get_uint64();
            break;

        case boost::json::kind::int64:
            os << jv.get_int64();
            break;

        case boost::json::kind::double_:
            os << jv.get_double();
            break;

        case boost::json::kind::bool_:
            if (jv.get_bool())
                os << "true";
            else
                os << "false";
            break;

        case boost::json::kind::null:
            os << "null";
            break;
    }

    if (indent->empty())
        os << "\n";
}

int main(int argc, char *argv[]) {

    typedef hashes::sha2<256> hash_type;
    typedef algebra::curves::curve25519 curve_type;
    typedef typename curve_type::template g1_type<> group_type;
    typedef pubkey::eddsa<group_type, pubkey::eddsa_type::basic, void> scheme_type;
    typedef pubkey::public_key<scheme_type> public_key_type;
    typedef pubkey::private_key<scheme_type> private_key_type;
    typedef typename pubkey::public_key<scheme_type>::signature_type signature_type;

    typedef multiprecision::number<multiprecision::cpp_int_backend<hash_type::digest_bits, hash_type::digest_bits,
                                                                   multiprecision::unsigned_magnitude>>
        hash_number_type;

    typedef boost::random::independent_bits_engine<boost::random::mt19937, hash_type::digest_bits, hash_number_type>
        random_hash_generator_type;

    boost::random::random_device rd;     // Will be used to obtain a seed for the random number engine
    boost::random::mt19937 gen(rd());    // Standard mersenne_twister_engine seeded with rd()
    boost::random::uniform_int_distribution<std::size_t> distrib(std::numeric_limits<std::size_t>::min() + 1, 1000UL);
    boost::random::uniform_int_distribution<std::size_t> small_distrib(std::numeric_limits<std::size_t>::min() + 1,
                                                                       10UL);

    random_hash_generator_type hash_gen;

    status_type s;

    state_type<hash_type, scheme_type> state {.confirmed = static_cast<size_t>(distrib(gen)),
                                              .new_confirmed = distrib(gen) + state.confirmed};

    for (int i = 0; i < distrib(gen); i++) {
        state.repl_data.push_back({
            .block_number = static_cast<size_t>(distrib(gen)),
            .bank_hash = pack<nil::marshalling::option::little_endian>(hash_gen(), s),
            .merkle_hash = pack<nil::marshalling::option::little_endian>(hash_gen(), s),
            .previous_bank_hash = pack<nil::marshalling::option::little_endian>(hash_gen(), s),

        });

        std::vector<uint64_t> slots;
        std::generate_n(std::back_inserter(slots), small_distrib(gen), [] {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                .count();
        });

        for (int j = 0; j < slots.size(); j++) {
            state.repl_data[i].votes.push_back({.slots = slots,
                                                .hash = pack<nil::marshalling::option::little_endian>(hash_gen(), s),
                                                .timestamp = static_cast<uint32_t>(slots[j]),
                                                .weight = static_cast<size_t>(distrib(gen))});
        }
    }

    for (int i = 0; i < distrib(gen); i++) {
        typename private_key_type::private_key_type pk = pack<nil::marshalling::option::little_endian>(hash_gen(), s);
        typename hash_type::digest_type data = pack<nil::marshalling::option::little_endian>(hash_gen(), s);

        state.signatures.emplace_back(sign<scheme_type>(data, private_key_type(pk)));
    }

    if (s == status_type::success) {
        boost::json::value jv = {
            {"confirmed", state.confirmed},
            {"new_confirmed", state.new_confirmed},
            {"repl_data", state.repl_data},
            {"signatures", std::accumulate(state.signatures.begin(), state.signatures.end(), boost::json::array {},
                                           [&](boost::json::array s, const signature_type &v) {
                                               s.emplace_back(std::to_string(v));
                                               return s;
                                           })}};

        pretty_print(std::cout, jv);
    }

    return 0;
}