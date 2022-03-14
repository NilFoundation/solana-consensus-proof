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

#include <boost/json/src.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/optional.hpp>

#ifndef __EMSCRIPTEN__
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#endif

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/alt_bn128.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>

#include <nil/crypto3/zk/components/algebra/curves/edwards/plonk/variable_base_endo_scalar_mul_15_wires.hpp>
#include <nil/crypto3/zk/components/hashes/poseidon/plonk/poseidon_15_wires.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/eddsa.hpp>

#include <nil/crypto3/zk/algorithms/generate.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/redshift/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/preprocessor.hpp>

#include <nil/crypto3/zk/math/non_linear_combination.hpp>

using namespace nil::crypto3;
using namespace nil::marshalling;

typedef algebra::curves::alt_bn128<254> curve_type;
typedef typename curve_type::base_field_type field_type;
constexpr static const std::size_t m = 2;
constexpr static const std::size_t k = 1;

constexpr static const std::size_t table_rows_log = 4;
constexpr static const std::size_t table_rows = 1 << table_rows_log;
constexpr static const std::size_t permutation_size = 4;
constexpr static const std::size_t usable_rows = 1 << table_rows_log;

struct redshift_params {
    using merkle_hash_type = hashes::keccak_1600<512>;
    using transcript_hash_type = hashes::keccak_1600<512>;

    constexpr static const std::size_t witness_columns = 3;
    constexpr static const std::size_t public_input_columns = 1;
    constexpr static const std::size_t constant_columns = 0;
    constexpr static const std::size_t selector_columns = 2;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t r = table_rows_log - 1;
    constexpr static const std::size_t m = 2;
};

constexpr static const std::size_t table_columns =
    redshift_params::witness_columns + redshift_params::public_input_columns;

typedef zk::commitments::fri<::field_type, redshift_params::merkle_hash_type, redshift_params::transcript_hash_type, m>
    fri_type;

typedef zk::snark::redshift_params<::field_type,
                                   redshift_params::witness_columns,
                                   redshift_params::public_input_columns,
                                   redshift_params::constant_columns,
                                   redshift_params::selector_columns>
    circuit_params;

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
block_data<Hash> tag_invoke(boost::json::value_to_tag<vote_state<Hash>>, const boost::json::value &jv) {
    auto &o = jv.as_object();
    return {.slots = o.at("slots").as_array(),
            .hash =
                [&](const boost::json::array &v) {
                    typename Hash::digest_type ret;
                    for (int i = 0; i < v.size(); i++) {
                        ret[i] = v[i].as_uint64();
                    }
                    return ret;
                }(o.at("hash").as_array()),
            .timestamp = o.at("timestamp").as_uint64()};
}

template<typename Hash>
block_data<Hash> tag_invoke(boost::json::value_to_tag<block_data<Hash>>, const boost::json::value &jv) {
    auto &o = jv.as_object();
    return {.block_number = o.at("block_number").as_uint64(),
            .bank_hash =
                [&](const boost::json::array &v) {
                    typename Hash::digest_type ret;
                    for (int i = 0; i < v.size(); i++) {
                        ret[i] = v[i].as_uint64();
                    }
                    return ret;
                }(o.at("bank_hash").as_array()),
            .merkle_hash =
                [&](const boost::json::array &v) {
                    typename Hash::digest_type ret;
                    for (int i = 0; i < v.size(); i++) {
                        ret[i] = v[i].as_uint64();
                    }
                    return ret;
                }(o.at("merkle_hash").as_array()),
            .previous_bank_hash =
                [&](const boost::json::array &v) {
                    typename Hash::digest_type ret;
                    for (int i = 0; i < v.size(); i++) {
                        ret[i] = v[i].as_uint64();
                    }
                    return ret;
                }(o.at("previous_bank_hash").as_array())};
}

template<typename Hash, typename SignatureSchemeType>
state_type<Hash, SignatureSchemeType> tag_invoke(boost::json::value_to_tag<state_type<Hash, SignatureSchemeType>>,
                                                 const boost::json::value &jv) {
    auto &o = jv.as_object();
    return {.confirmed = o.at("confirmed").as_uint64(),
            .new_confirmed = o.at("new_confirmed").as_uint64(),
            .repl_data =
                [&](const boost::json::value &arr) {
                    std::vector<block_data<Hash>> ret;
                    for (const boost::json::value &val : arr.as_array()) {
                        ret.emplace_back(boost::json::value_to<block_data<Hash>>(val));
                    }
                    return ret;
                }(o.at("repl_data")),
            .signatures =
                [&](const boost::json::value &arr) {
                    std::vector<typename pubkey::public_key<SignatureSchemeType>::signature_type> ret;
                    for (const boost::json::value &val : arr.as_array()) {
                        typename pubkey::public_key<SignatureSchemeType>::signature_type sig;
                        std::istringstream istr(val.as_string().data());
                        istr >> sig;
                        ret.emplace_back(sig);
                    }
                    return ret;
                }(o.at("signatures"))};
}

int main(int argc, char *argv[]) {

    typedef hashes::sha2<256> hash_type;
    typedef algebra::curves::alt_bn128<254> system_curve_type;
    typedef algebra::curves::curve25519 signature_curve_type;
    typedef typename signature_curve_type::template g1_type<> group_type;
    typedef pubkey::eddsa<group_type, pubkey::eddsa_type::basic, void> signature_scheme_type;
    typedef typename pubkey::public_key<signature_scheme_type>::signature_type signature_type;

    state_type<hash_type, signature_scheme_type> state;

    std::string string;

#ifndef __EMSCRIPTEN__
    boost::program_options::options_description options("Solana 'Light-Client' State Proof Generator");
    // clang-format off
    options.add_options()("help,h", "Display help message")
    ("version,v", "Display version")
    ("output,o", "Output file");
    // clang-format on

    boost::program_options::positional_options_description p;
    p.add("input", 1);

    boost::program_options::variables_map vm;
    boost::program_options::store(
        boost::program_options::command_line_parser(argc, argv).options(options).positional(p).run(), vm);
    boost::program_options::notify(vm);

    if (vm.count("help") || argc < 2) {
        std::cout << options << std::endl;
        return 0;
    }

    if (vm.count("input")) {
        if (boost::filesystem::exists(vm["input"].as<std::string>())) {
            boost::filesystem::load_string_file(vm["input"].as<std::string>(), string);
        }
    } else {
        std::cin >> string;
    }
#else
    std::cin >> string;
#endif

    {
        boost::json::monotonic_resource mr;
        state = boost::json::value_to<state_type<hash_type, signature_scheme_type>>(boost::json::parse(string, &mr));
    }

    constexpr typename curve_type::template g1_type<>::value_type B = curve_type::template g1_type<>::value_type::one();
    using ArithmetizationType = zk::snark::plonk_constraint_system<::field_type>;

    zk::blueprint<ArithmetizationType> bp;
    zk::blueprint_private_assignment_table<ArithmetizationType, redshift_params::witness_columns> private_assignment;
    zk::blueprint_public_assignment_table<ArithmetizationType,
                                          redshift_params::public_input_columns,
                                          redshift_params::constant_columns,
                                          redshift_params::selector_columns>
        public_assignment;

    zk::components::curve_element_variable_base_endo_scalar_mul<ArithmetizationType,
                                                                curve_type,
                                                                0,
                                                                1,
                                                                2,
                                                                3,
                                                                4,
                                                                5,
                                                                6,
                                                                7,
                                                                8,
                                                                9,
                                                                10,
                                                                11,
                                                                12,
                                                                13,
                                                                14>
        scalar_mul_component(bp);
    zk::components::poseidon_plonk<ArithmetizationType, curve_type> poseidon_component(bp);

//    scalar_mul_component.generate_gates(public_assignment);
//    poseidon_component.generate_gates();

    typename curve_type::scalar_field_type::value_type a = curve_type::scalar_field_type::value_type::one();
    typename curve_type::template g1_type<>::value_type P = curve_type::template g1_type<>::value_type::one();

    scalar_mul_component.generate_assignments(private_assignment, public_assignment, {P, a});
    poseidon_component.generate_assignments();

    //    auto cs = bp.get_constraint_system();

    //    auto assignments = bp.full_variable_assignment();

    //    typedef zk::snark::redshift_preprocessor<typename curve_type::base_field_type, 15, 1> preprocessor_type;
    //    typedef zk::snark::redshift_prover<typename curve_type::base_field_type, 15, 5, 1, 5> prover_type;

    //    auto proof = prover_type::process(preprocessor_type::process(cs, assignments), cs, assignments);

#ifndef __EMSCRIPTEN__
    if (vm.count("output")) {
    }
#else

#endif

    return 0;
}