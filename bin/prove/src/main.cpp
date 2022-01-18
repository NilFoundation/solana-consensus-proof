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

#include <nil/crypto3/algebra/curves/curve25519.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/alt_bn128.hpp>

#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/hashes/plonk/poseidon_5_wires.hpp>
#include <nil/crypto3/zk/components/algebra/curves/plonk/fixed_base_scalar_mul_5_wires.hpp>
#include <nil/crypto3/zk/components/algebra/curves/plonk/variable_base_scalar_mul_5_wires.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/eddsa.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/redshift/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/preprocessor.hpp>
#include <nil/crypto3/zk/snark/relations/non_linear_combination.hpp>

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
    typedef Hash hash_type;
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
    typedef pubkey::eddsa<group_type, pubkey::EddsaVariant::basic, void> signature_scheme_type;
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
    }
#else
    std::cin >> string;
#endif

    {
        boost::json::monotonic_resource mr;
        state = boost::json::value_to<state_type<hash_type, signature_scheme_type>>(boost::json::parse(string, &mr));
    }

    using TBlueprintField = typename system_curve_type::base_field_type;
    constexpr std::size_t WiresAmount = 5;
    constexpr typename system_curve_type::template g1_type<>::value_type B =
        system_curve_type::template g1_type<>::value_type::one();
    using TArithmetization = zk::snark::plonk_constraint_system<TBlueprintField, WiresAmount>;

    zk::components::blueprint<TArithmetization> bp;

    zk::components::element_g1_fixed_base_scalar_mul<TArithmetization, system_curve_type> scalar_mul_component(bp, B);
    zk::components::poseidon_plonk<TArithmetization, system_curve_type> poseidon_component(bp);

    scalar_mul_component.generate_gates();

    typename system_curve_type::scalar_field_type::value_type a =
        system_curve_type::scalar_field_type::value_type::one();
    typename system_curve_type::template g1_type<>::value_type P =
        system_curve_type::template g1_type<>::value_type::one();

    scalar_mul_component.generate_assignments(a, P);

    auto cs = bp.get_constraint_system();

    auto assignments = bp.full_variable_assignment();

    typedef zk::snark::redshift_preprocessor<typename system_curve_type::base_field_type, 5, 1> preprocess_type;

    auto preprocessed_data = preprocess_type::process(cs, assignments);
    typedef zk::snark::redshift_prover<typename system_curve_type::base_field_type, 5, 5, 1, 5> prove_type;
    auto proof = prove_type::process(preprocessed_data, cs, assignments);

#ifndef __EMSCRIPTEN__
    if (vm.count("output")) {
    }
#else

#endif

    return 0;
}