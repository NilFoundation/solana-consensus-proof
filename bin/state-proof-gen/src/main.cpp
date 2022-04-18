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

#include <boost/random.hpp>
#include <boost/random/random_device.hpp>
#include <boost/json/src.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/optional.hpp>

#ifndef __EMSCRIPTEN__
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#endif

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/alt_bn128.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/unified_addition.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/variable_base_endo_scalar_mul_15_wires.hpp>
#include <nil/crypto3/zk/components/hashes/poseidon/plonk/poseidon_15_wires.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/eddsa.hpp>

#include <nil/crypto3/zk/commitments/type_traits.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/params.hpp>

#include <nil/marshalling/endianness.hpp>
#include <nil/crypto3/marshalling/zk/types/redshift/proof.hpp>

#include <nil/actor/core/app_template.hh>

#include <fstream>

using namespace nil;
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

    std::size_t weight;
};

template<typename Hash>
struct block_data {
    typedef Hash hash_type;
    typedef typename Hash::digest_type digest_type;

    std::size_t block_number;
    digest_type bank_hash;
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
vote_state<Hash> tag_invoke(boost::json::value_to_tag<vote_state<Hash>>, const boost::json::value &jv) {
    auto &o = jv.as_object();
    return {.slots =
                [&](const boost::json::value &arr) {
                    std::vector<std::uint64_t> ret;
                    for (const boost::json::value &val : arr.as_array()) {
                        ret.emplace_back(boost::json::value_to<std::uint64_t>(val));
                    }
                    return ret;
                }(o.at("slots")),
            .hash =
                [&](const boost::json::value &v) {
                    typename Hash::digest_type ret;
                    std::istringstream istr(boost::json::value_to<std::string>(v));
                    istr >> ret;
                    return ret;
                }(o.at("hash")),
            .timestamp = boost::json::value_to<std::uint32_t>(o.at("timestamp")),
            .weight = boost::json::value_to<std::size_t>(o.at("weight"))};
}

template<typename Hash>
block_data<Hash> tag_invoke(boost::json::value_to_tag<block_data<Hash>>, const boost::json::value &jv) {
    auto &o = jv.as_object();

    return {
        .block_number = boost::json::value_to<std::size_t>(o.at("block_number")),
        .bank_hash =
            [&](const boost::json::value &v) {
                typename Hash::digest_type ret;
                std::istringstream istr(boost::json::value_to<std::string>(v));
                istr >> ret;
                return ret;
            }(o.at("bank_hash")),
        .previous_bank_hash =
            [&](const boost::json::value &v) {
                typename Hash::digest_type ret;
                std::istringstream istr(boost::json::value_to<std::string>(v));
                istr >> ret;
                return ret;
            }(o.at("previous_bank_hash")),
        .votes =
            [&](const boost::json::value &arr) {
                std::vector<vote_state<Hash>> ret;
                for (const boost::json::value &val : arr.as_array()) {
                    ret.emplace_back(boost::json::value_to<vote_state<Hash>>(val));
                }
                return ret;
            }(o.at("votes")),

    };
}

template<typename Hash, typename SignatureSchemeType>
state_type<Hash, SignatureSchemeType> tag_invoke(boost::json::value_to_tag<state_type<Hash, SignatureSchemeType>>,
                                                 const boost::json::value &jv) {
    auto &o = jv.as_object();
    return {.confirmed = boost::json::value_to<std::size_t>(o.at("confirmed")),
            .new_confirmed = boost::json::value_to<std::size_t>(o.at("new_confirmed")),
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

template<typename fri_type, typename FieldType>
typename fri_type::params_type create_fri_params(std::size_t degree_log) {
    typename fri_type::params_type params;
    math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

    constexpr std::size_t expand_factor = 0;
    std::size_t r = degree_log - 1;

    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
        zk::commitments::detail::calculate_domain_set<FieldType>(degree_log + expand_factor, r);

    params.r = r;
    params.D = domain_set;
    params.q = q;
    params.max_degree = (1 << degree_log) - 1;

    return params;
}

template<typename TIter>
void print_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end) {
    os << "0x";
    os << std::hex;
    for (TIter it = iter_begin; it != iter_end; it++) {
        os << std::setfill('0') << std::setw(2) << std::right << int(*it);
    }
    os << std::endl << std::dec;
}

template<typename Endianness, typename RedshiftProof>
std::vector<std::uint8_t> serialize_proof(const RedshiftProof &proof) {
    using namespace nil::crypto3::marshalling;

    auto filled_redshift_proof =
        nil::crypto3::marshalling::types::fill_redshift_proof<RedshiftProof, Endianness>(proof);
    RedshiftProof _proof =
        nil::crypto3::marshalling::types::make_redshift_proof<RedshiftProof, Endianness>(filled_redshift_proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_redshift_proof.length(), 0x00);
    auto write_iter = cv.begin();

    if (filled_redshift_proof.write(write_iter, cv.size()) == status_type::success) {
        return cv;
    } else {
        return {};
    }
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
    ("output,o", boost::program_options::value<std::string>(),"Output file")
    ("input,i", boost::program_options::value<std::string>(), "Input file")
    ("parallel,j", boost::program_options::value<std::size_t>()->default_value(1), "Prover threads amount");
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
        if (vm["input"].as<std::string>().size() < PATH_MAX || vm["input"].as<std::string>().size() < FILENAME_MAX) {
            if (boost::filesystem::exists(vm["input"].as<std::string>())) {
                boost::filesystem::load_string_file(vm["input"].as<std::string>(), string);
            }
        } else {
            string = vm["input"].as<std::string>();
        }
    } else {
        std::string line;

        while (std::getline(std::cin, line)) {
            string += line + "\n";
        }
    }
#else
    std::string line;

    while (std::getline(std::cin, line)) {
        string += line + "\n";
    }
#endif

    {
        boost::json::monotonic_resource mr;
        state = boost::json::value_to<state_type<hash_type, signature_scheme_type>>(boost::json::parse(string, &mr));
    }

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 11;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using arithmetization_params =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    typedef zk::snark::plonk_constraint_system<BlueprintFieldType, arithmetization_params> arithmetization_type;

    typedef zk::components::curve_element_unified_addition<arithmetization_type, curve_type, 0, 1, 2, 3, 4, 5, 6, 7, 8,
                                                           9, 10>
        component_type;

    auto P = algebra::random_element<curve_type::template g1_type<>>().to_affine();
    auto Q = algebra::random_element<curve_type::template g1_type<>>().to_affine();

    typename component_type::params_type params = {
        {zk::snark::plonk_variable<BlueprintFieldType>(
             0, 1, false, zk::snark::plonk_variable<BlueprintFieldType>::column_type::public_input),
         zk::snark::plonk_variable<BlueprintFieldType>(
             0, 2, false, zk::snark::plonk_variable<BlueprintFieldType>::column_type::public_input)},
        {zk::snark::plonk_variable<BlueprintFieldType>(
             0, 3, false, zk::snark::plonk_variable<BlueprintFieldType>::column_type::public_input),
         zk::snark::plonk_variable<BlueprintFieldType>(
             0, 4, false, zk::snark::plonk_variable<BlueprintFieldType>::column_type::public_input)}};

    std::vector<typename BlueprintFieldType::value_type> public_input = {0, P.X, P.Y, Q.X, Q.Y};

    typename component_type::allocated_data_type allocated;
    zk::snark::plonk_table_description<BlueprintFieldType, arithmetization_params> desc;

    zk::blueprint<arithmetization_type> bp(desc);
    zk::blueprint_private_assignment_table<arithmetization_type> private_assignment(desc);
    zk::blueprint_public_assignment_table<arithmetization_type> public_assignment(desc);
    zk::blueprint_assignment_table<arithmetization_type> assignment_bp(private_assignment, public_assignment);

    std::size_t start_row = component_type::allocate_rows(bp);
    component_type::generate_circuit(bp, assignment_bp, params, allocated, start_row);
    component_type::generate_assignments(assignment_bp, params, start_row);

    private_assignment.padding();
    public_assignment.padding();

    zk::snark::plonk_assignment_table<BlueprintFieldType, arithmetization_params> assignments(private_assignment,
                                                                                              public_assignment);

    using params_type = zk::snark::redshift_params<BlueprintFieldType, arithmetization_params, hashes::keccak_1600<256>,
                                                   hashes::keccak_1600<256>, 1>;
    using policy_type = zk::snark::detail::redshift_policy<BlueprintFieldType, params_type>;

    using fri_type = typename zk::commitments::fri<BlueprintFieldType, typename params_type::merkle_hash_type,
                                                   typename params_type::transcript_hash_type, 2>;

    std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));

    typename fri_type::params_type fri_params = create_fri_params<fri_type, BlueprintFieldType>(table_rows_log);

    if (vm.count("parallel") && vm["parallel"].as<std::size_t>() == 1) {
        std::size_t permutation_size =
            zk::snark::plonk_table_description<BlueprintFieldType, arithmetization_params>::witness_columns +
            zk::snark::plonk_table_description<BlueprintFieldType, arithmetization_params>::public_input_columns +
            zk::snark::plonk_table_description<BlueprintFieldType, arithmetization_params>::constant_columns;

        typename policy_type::preprocessed_public_data_type public_preprocessed_data =
            zk::snark::redshift_public_preprocessor<BlueprintFieldType, params_type>::process(
                bp, public_assignment, desc, fri_params, permutation_size);
        typename policy_type::preprocessed_private_data_type private_preprocessed_data =
            zk::snark::redshift_private_preprocessor<BlueprintFieldType, params_type>::process(bp, private_assignment,
                                                                                               desc);

        auto proof = zk::snark::redshift_prover<BlueprintFieldType, params_type>::process(
            public_preprocessed_data, private_preprocessed_data, desc, bp, assignments, fri_params);

        if (!zk::snark::redshift_verifier<BlueprintFieldType, params_type>::process(public_preprocessed_data, proof, bp,
                                                                                    fri_params)) {
            return -1;
        }

        auto cv = serialize_proof<option::big_endian>(proof);

#ifndef __EMSCRIPTEN__

        if (vm.count("output")) {
            print_byteblob(std::cout, cv.cbegin(), cv.cend());
        } else {
            std::ofstream of(vm["output"].as<std::string>());
            print_byteblob(of, cv.begin(), cv.end());
        }
#else
        print_byteblob(std::cout, cv.cbegin(), cv.cend());
#endif
    } else {
        actor::app_template app;
        app.run(argc, argv, [&] {
            std::cout << "Hello world\n";

#ifndef __EMSCRIPTEN__
            if (vm.count("output")) {
                //        using Endianness = nil::marshalling::option::big_endian;
                //        serialize_proof<Endianness>(proof);
            }
#else

#endif
            return actor::make_ready_future<>();
        });
    }
}