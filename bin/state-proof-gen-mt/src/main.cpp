//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#define BOOST_APPLICATION_FEATURE_NS_SELECT_BOOST

#include <boost/application.hpp>

#undef B0

#include <boost/random.hpp>
#include <boost/random/random_device.hpp>
#include <boost/json/src.hpp>
#include <boost/optional.hpp>

#include <nil/actor/core/app_template.hh>
#include <nil/actor/core/reactor.hh>
#include <nil/actor/core/metrics_api.hh>
#include <nil/actor/core/print.hh>

#include <nil/actor/core/thread.hh>
#include <nil/actor/core/with_scheduling_group.hh>

#include <fstream>

#include <nil/state-proof-gen-mt/aspects/actor.hpp>
#include <nil/state-proof-gen-mt/aspects/args.hpp>
#include <nil/state-proof-gen-mt/aspects/path.hpp>
#include <nil/state-proof-gen-mt/aspects/configuration.hpp>
#include <nil/state-proof-gen-mt/aspects/proof.hpp>
#include <nil/state-proof-gen-mt/detail/configurable.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/actor/zk/components/hashes/sha256/plonk/sha256_process.hpp>    // sha256
#include <nil/actor/zk/assignment/plonk.hpp>

#include <nil/actor/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/actor/zk/algorithms/allocate.hpp>

#include <nil/actor/zk/components/non_native/algebra/fields/plonk/fixed_base_multiplication_edwards25519.hpp>

#include <nil/actor/zk/components/hashes/sha256/plonk/sha512_process.hpp>

#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>
#include <nil/actor/zk/components/non_native/algebra/fields/plonk/variable_base_multiplication_edwards25519.hpp>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/eddsa.hpp>

#include <nil/state-proof-gen-mt/test_plonk_component.hpp>

using namespace nil::actor;

template<typename F, typename First, typename... Rest>
inline void insert_aspect(F f, First first, Rest... rest) {
    f(first);
    insert_aspect(f, rest...);
}

template<typename F>
inline void insert_aspect(F f) {
}

template<typename Application, typename... Aspects>
inline bool insert_aspects(boost::application::context &ctx, Application &app, Aspects... args) {
    insert_aspect([&](auto aspect) { ctx.insert<typename decltype(aspect)::element_type>(aspect); }, args...);

    boost::shared_ptr<nil::proof::aspects::path> path_aspect = boost::make_shared<nil::proof::aspects::path>();

    ctx.insert<nil::proof::aspects::path>(path_aspect);
    ctx.insert<nil::proof::aspects::configuration>(boost::make_shared<nil::proof::aspects::configuration>(path_aspect));
    ctx.insert<nil::proof::aspects::actor>(boost::make_shared<nil::proof::aspects::actor>(path_aspect));
    ctx.insert<nil::proof::aspects::proof>(boost::make_shared<nil::proof::aspects::proof>(path_aspect));

    return true;
}

template<typename Application>
inline bool configure_aspects(boost::application::context &ctx, Application &app) {
    typedef nil::proof::detail::configurable<nil::dbms::plugin::variables_map,
                                             nil::dbms::plugin::cli_options_description,
                                             nil::dbms::plugin::cfg_options_description>
        configurable_aspect_type;

    boost::strict_lock<boost::application::aspect_map> guard(ctx);
    boost::shared_ptr<nil::proof::aspects::args> args = ctx.find<nil::proof::aspects::args>(guard);
    boost::shared_ptr<nil::proof::aspects::configuration> cfg = ctx.find<nil::proof::aspects::configuration>(guard);

    for (boost::shared_ptr<void> itr : ctx) {
        boost::static_pointer_cast<configurable_aspect_type>(itr)->set_options(cfg->cli());
        boost::static_pointer_cast<configurable_aspect_type>(itr)->set_options(cfg->cfg());
    }

    try {
        boost::program_options::store(
            boost::program_options::parse_command_line(args->argc(), args->argv(), cfg->cli()), cfg->vm());
    } catch (const std::exception &e) {
        std::cout << e.what() << std::endl;
    }

    for (boost::shared_ptr<void> itr : ctx) {
        boost::static_pointer_cast<configurable_aspect_type>(itr)->initialize(cfg->vm());
    }

    return false;
}

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
    typedef typename nil::crypto3::pubkey::public_key<signature_scheme_type>::signature_type signature_type;

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
                    std::vector<typename nil::crypto3::pubkey::public_key<SignatureSchemeType>::signature_type> ret;
                    for (const boost::json::value &val : arr.as_array()) {
                        typename nil::crypto3::pubkey::public_key<SignatureSchemeType>::signature_type sig;
                        std::istringstream istr(val.as_string().data());
                        istr >> sig;
                        ret.emplace_back(sig);
                    }
                    return ret;
                }(o.at("signatures"))};
}

template<typename Hash, typename SignatureScheme>
void sha256_process(const state_type<Hash, SignatureScheme> &state) {
    using curve_type = nil::crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 10;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;

    using component_type = zk::components::sha256_process<ArithmetizationType, curve_type, 0, 1, 2, 3, 4, 5, 6, 7, 8>;
    typename BlueprintFieldType::value_type s = typename BlueprintFieldType::value_type(2).pow(29);
    std::array<typename ArithmetizationType::field_type::value_type, 24> public_input = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        s - 5,      s + 5,      s - 6,      s + 6,      s - 7,      s + 7,      s - 8,      s + 8,
        s - 9,      s + 9,      s + 10,     s - 10,     s + 11,     s - 11,     s + 12,     s - 12};
    std::array<var, 8> input_state_var = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input),
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

    std::array<typename BlueprintFieldType::integral_type, 64> round_constant = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    std::array<var, 16> input_words_var;
    for (int i = 0; i < 16; i++) {
        input_words_var[i] = var(0, 8 + i, false, var::column_type::public_input);
    }
    std::array<typename BlueprintFieldType::integral_type, 64> message_schedule_array;
    for (std::size_t i = 0; i < 16; i++) {
        message_schedule_array[i] = typename BlueprintFieldType::integral_type(public_input[8 + i].data);
    }
    for (std::size_t i = 16; i < 64; i++) {
        typename BlueprintFieldType::integral_type s0 =
            ((message_schedule_array[i - 15] >> 7) |
             ((message_schedule_array[i - 15] << (32 - 7)) &
              typename BlueprintFieldType::integral_type(
                  (typename BlueprintFieldType::value_type(2).pow(32) - 1).data))) ^
            ((message_schedule_array[i - 15] >> 18) |
             ((message_schedule_array[i - 15] << (32 - 18)) &
              typename BlueprintFieldType::integral_type(
                  (typename BlueprintFieldType::value_type(2).pow(32) - 1).data))) ^
            (message_schedule_array[i - 15] >> 3);
        typename BlueprintFieldType::integral_type s1 =
            ((message_schedule_array[i - 2] >> 17) |
             ((message_schedule_array[i - 2] << (32 - 17)) &
              typename BlueprintFieldType::integral_type(
                  (typename BlueprintFieldType::value_type(2).pow(32) - 1).data))) ^
            ((message_schedule_array[i - 2] >> 19) |
             ((message_schedule_array[i - 2] << (32 - 19)) &
              typename BlueprintFieldType::integral_type(
                  (typename BlueprintFieldType::value_type(2).pow(32) - 1).data))) ^
            (message_schedule_array[i - 2] >> 10);
        message_schedule_array[i] = (message_schedule_array[i - 16] + s0 + s1 + message_schedule_array[i - 7]) %
                                    typename curve_type::base_field_type::integral_type(
                                        typename curve_type::base_field_type::value_type(2).pow(32).data);
    }
    typename ArithmetizationType::field_type::integral_type a =
        typename ArithmetizationType::field_type::integral_type(public_input[0].data);
    typename ArithmetizationType::field_type::integral_type b =
        typename ArithmetizationType::field_type::integral_type(public_input[1].data);
    typename ArithmetizationType::field_type::integral_type c =
        typename ArithmetizationType::field_type::integral_type(public_input[2].data);
    typename ArithmetizationType::field_type::integral_type d =
        typename ArithmetizationType::field_type::integral_type(public_input[3].data);
    typename ArithmetizationType::field_type::integral_type e =
        typename ArithmetizationType::field_type::integral_type(public_input[4].data);
    typename ArithmetizationType::field_type::integral_type f =
        typename ArithmetizationType::field_type::integral_type(public_input[5].data);
    typename ArithmetizationType::field_type::integral_type g =
        typename ArithmetizationType::field_type::integral_type(public_input[6].data);
    typename ArithmetizationType::field_type::integral_type h =
        typename ArithmetizationType::field_type::integral_type(public_input[7].data);
    for (std::size_t i = 0; i < 64; i++) {
        typename BlueprintFieldType::integral_type S0 =
            ((a >> 2) | ((a << (32 - 2)) & typename BlueprintFieldType::integral_type(
                                               (typename BlueprintFieldType::value_type(2).pow(32) - 1).data))) ^
            ((a >> 13) | ((a << (32 - 13)) & typename BlueprintFieldType::integral_type(
                                                 (typename BlueprintFieldType::value_type(2).pow(32) - 1).data))) ^
            ((a >> 22) | ((a << (32 - 22)) & typename BlueprintFieldType::integral_type(
                                                 (typename BlueprintFieldType::value_type(2).pow(32) - 1).data)));
        typename BlueprintFieldType::integral_type S1 =
            ((e >> 6) | ((e << (32 - 6)) & typename BlueprintFieldType::integral_type(
                                               (typename BlueprintFieldType::value_type(2).pow(32) - 1).data))) ^
            ((e >> 11) | ((e << (32 - 11)) & typename BlueprintFieldType::integral_type(
                                                 (typename BlueprintFieldType::value_type(2).pow(32) - 1).data))) ^
            ((e >> 25) | ((e << (32 - 25)) & typename BlueprintFieldType::integral_type(
                                                 (typename BlueprintFieldType::value_type(2).pow(32) - 1).data)));
        typename BlueprintFieldType::integral_type maj = (a & b) ^ (a & c) ^ (b & c);
        typename BlueprintFieldType::integral_type ch = (e & f) ^ ((~e) & g);
        typename BlueprintFieldType::integral_type tmp1 = h + S1 + ch + round_constant[i] + message_schedule_array[i];
        typename BlueprintFieldType::integral_type tmp2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = (d + tmp1) % typename curve_type::base_field_type::integral_type(
                             typename curve_type::base_field_type::value_type(2).pow(32).data);
        d = c;
        c = b;
        b = a;
        a = (tmp1 + tmp2) % typename curve_type::base_field_type::integral_type(
                                typename curve_type::base_field_type::value_type(2).pow(32).data);
    }
    std::array<typename BlueprintFieldType::integral_type, 8> result_state = {
        (a + typename ArithmetizationType::field_type::integral_type(public_input[0].data)) %
            typename curve_type::base_field_type::integral_type(
                typename curve_type::base_field_type::value_type(2).pow(32).data),
        (b + typename ArithmetizationType::field_type::integral_type(public_input[1].data)) %
            typename curve_type::base_field_type::integral_type(
                typename curve_type::base_field_type::value_type(2).pow(32).data),
        (c + typename ArithmetizationType::field_type::integral_type(public_input[2].data)) %
            typename curve_type::base_field_type::integral_type(
                typename curve_type::base_field_type::value_type(2).pow(32).data),
        (d + typename ArithmetizationType::field_type::integral_type(public_input[3].data)) %
            typename curve_type::base_field_type::integral_type(
                typename curve_type::base_field_type::value_type(2).pow(32).data),
        (e + typename ArithmetizationType::field_type::integral_type(public_input[4].data)) %
            typename curve_type::base_field_type::integral_type(
                typename curve_type::base_field_type::value_type(2).pow(32).data),
        (f + typename ArithmetizationType::field_type::integral_type(public_input[5].data)) %
            typename curve_type::base_field_type::integral_type(
                typename curve_type::base_field_type::value_type(2).pow(32).data),
        (g + typename ArithmetizationType::field_type::integral_type(public_input[6].data)) %
            typename curve_type::base_field_type::integral_type(
                typename curve_type::base_field_type::value_type(2).pow(32).data),
        (h + typename ArithmetizationType::field_type::integral_type(public_input[7].data)) %
            typename curve_type::base_field_type::integral_type(
                typename curve_type::base_field_type::value_type(2).pow(32).data)};
    auto result_check = [result_state](AssignmentType &assignment, component_type::result_type &real_res) {
        for (std::size_t i = 0; i < 8; i++) {
            assert(result_state[i] == typename ArithmetizationType::field_type::integral_type(
                                          assignment.var_value(real_res.output_state[i]).data));
        }
    };
    typename component_type::params_type params = {input_state_var, input_words_var};
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

template<typename Hash, typename SignatureScheme>
void non_native_demo(const state_type<Hash, SignatureScheme> &state) {
    constexpr std::size_t complexity = 1;

    using curve_type = nil::crypto3::algebra::curves::pallas;
    using ed25519_type = nil::crypto3::algebra::curves::ed25519;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 17;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using mul_component_type = zk::components::variable_base_multiplication<ArithmetizationType, curve_type,
                                                                            ed25519_type, 0, 1, 2, 3, 4, 5, 6, 7, 8>;
    using sha256_component_type =
        zk::components::sha256_process<ArithmetizationType, curve_type, 0, 1, 2, 3, 4, 5, 6, 7, 8>;
    typename BlueprintFieldType::value_type s = typename BlueprintFieldType::value_type(2).pow(29);

    std::array<var, 8> input_state_var = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input),
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};
    std::array<var, 16> input_words_var;
    for (int i = 0; i < 16; i++) {
        input_words_var[i] = var(0, 8 + i, false, var::column_type::public_input);
    }
    typename sha256_component_type::params_type sha_params = {input_state_var, input_words_var};

    std::array<var, 4> input_var_Xa = {
        var(0, 24, false, var::column_type::public_input), var(0, 25, false, var::column_type::public_input),
        var(0, 26, false, var::column_type::public_input), var(0, 27, false, var::column_type::public_input)};
    std::array<var, 4> input_var_Xb = {
        var(0, 28, false, var::column_type::public_input), var(0, 29, false, var::column_type::public_input),
        var(0, 30, false, var::column_type::public_input), var(0, 31, false, var::column_type::public_input)};

    var b_var = var(0, 32, false, var::column_type::public_input);

    typename mul_component_type::params_type mul_params = {{input_var_Xa, input_var_Xb}, b_var};

    ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type T =
        nil::crypto3::algebra::random_element<
            ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>>();
    ed25519_type::scalar_field_type::value_type b =
        nil::crypto3::algebra::random_element<ed25519_type::scalar_field_type>();
    ed25519_type::base_field_type::integral_type integral_b = ed25519_type::base_field_type::integral_type(b.data);
    ed25519_type::base_field_type::integral_type Tx = ed25519_type::base_field_type::integral_type(T.X.data);
    ed25519_type::base_field_type::integral_type Ty = ed25519_type::base_field_type::integral_type(T.Y.data);
    typename ed25519_type::base_field_type::integral_type base = 1;
    typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;

    std::array<typename ArithmetizationType::field_type::value_type, 33> public_input = {0x6a09e667,
                                                                                         0xbb67ae85,
                                                                                         0x3c6ef372,
                                                                                         0xa54ff53a,
                                                                                         0x510e527f,
                                                                                         0x9b05688c,
                                                                                         0x1f83d9ab,
                                                                                         0x5be0cd19,
                                                                                         s - 5,
                                                                                         s + 5,
                                                                                         s - 6,
                                                                                         s + 6,
                                                                                         s - 7,
                                                                                         s + 7,
                                                                                         s - 8,
                                                                                         s + 8,
                                                                                         s - 9,
                                                                                         s + 9,
                                                                                         s + 10,
                                                                                         s - 10,
                                                                                         s + 11,
                                                                                         s - 11,
                                                                                         s + 12,
                                                                                         s - 12,
                                                                                         Tx & mask,
                                                                                         (Tx >> 66) & mask,
                                                                                         (Tx >> 132) & mask,
                                                                                         (Tx >> 198) & mask,
                                                                                         Ty & mask,
                                                                                         (Ty >> 66) & mask,
                                                                                         (Ty >> 132) & mask,
                                                                                         (Ty >> 198) & mask,
                                                                                         integral_b};

    zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> desc;

    zk::blueprint<ArithmetizationType> bp(desc);
    zk::blueprint_private_assignment_table<ArithmetizationType> private_assignment(desc);
    zk::blueprint_public_assignment_table<ArithmetizationType> public_assignment(desc);
    zk::blueprint_assignment_table<ArithmetizationType> assignment_bp(private_assignment, public_assignment);

    std::size_t start_row = 0;
    zk::components::allocate<sha256_component_type>(bp, 1);
    zk::components::allocate<mul_component_type>(bp, complexity);

    bp.allocate_rows(public_input.size());

    sha256_component_type::generate_circuit(bp, public_assignment, sha_params, start_row);
    sha256_component_type::generate_assignments(assignment_bp, sha_params, start_row);
    start_row += sha256_component_type::rows_amount;

    for (std::size_t i = 0; i < complexity; i++) {

        std::size_t row = start_row + i * mul_component_type::rows_amount;

        mul_component_type::generate_circuit(bp, public_assignment, mul_params, row);

        mul_component_type::generate_assignments(assignment_bp, mul_params, row);
    }

    assignment_bp.padding();

    zk::snark::plonk_assignment_table<BlueprintFieldType, ArithmetizationParams> assignments(private_assignment,
                                                                                             public_assignment);

    // profiling(assignments);
    using params =
        zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, hash_type, hash_type, Lambda>;

    using fri_type = typename zk::commitments::fri<BlueprintFieldType, typename params::merkle_hash_type,
                                                   typename params::transcript_hash_type, 2, 1>;

    std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));

    typename fri_type::params_type fri_params = create_fri_params<fri_type, BlueprintFieldType>(table_rows_log);

    std::size_t permutation_size = desc.witness_columns + desc.public_input_columns + desc.constant_columns;

    typename zk::snark::placeholder_public_preprocessor<BlueprintFieldType, params>::preprocessed_data_type
        public_preprocessed_data = zk::snark::placeholder_public_preprocessor<BlueprintFieldType, params>::process(
                                       bp, public_assignment, desc, fri_params, permutation_size)
                                       .get();
    typename zk::snark::placeholder_private_preprocessor<BlueprintFieldType, params>::preprocessed_data_type
        private_preprocessed_data = zk::snark::placeholder_private_preprocessor<BlueprintFieldType, params>::process(
                                        bp, private_assignment, desc, fri_params)
                                        .get();

    auto placeholder_proof = zk::snark::placeholder_prover<BlueprintFieldType, params>::process(
        public_preprocessed_data, private_preprocessed_data, desc, bp, assignments, fri_params);

    bool verifier_res = zk::snark::placeholder_verifier<BlueprintFieldType, params>::process(
        public_preprocessed_data, placeholder_proof, bp, fri_params);
    std::cout << "Proof check: " << verifier_res << std::endl;
}

template<typename Hash, typename SignatureScheme>
void sha512_process(const state_type<Hash, SignatureScheme> &state) {
    using curve_type = nil::crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 10;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;

    using component_type = zk::components::sha512_process<ArithmetizationType, curve_type, 0, 1, 2, 3, 4, 5, 6, 7, 8>;
    typename BlueprintFieldType::value_type s = typename BlueprintFieldType::value_type(2).pow(59);
    std::array<typename ArithmetizationType::field_type::value_type, 24> public_input = {0x6a09e667f3bcc908_cppui64,
                                                                                         0xbb67ae8584caa73b_cppui64,
                                                                                         0x3c6ef372fe94f82b_cppui64,
                                                                                         0xa54ff53a5f1d36f1_cppui64,
                                                                                         0x510e527fade682d1_cppui64,
                                                                                         0x9b05688c2b3e6c1f_cppui64,
                                                                                         0x1f83d9abfb41bd6b_cppui64,
                                                                                         0x5be0cd19137e2179_cppui64,
                                                                                         s - 5,
                                                                                         s + 5,
                                                                                         s - 6,
                                                                                         s + 6,
                                                                                         s - 7,
                                                                                         s + 7,
                                                                                         s - 8,
                                                                                         s + 8,
                                                                                         s - 9,
                                                                                         s + 9,
                                                                                         s + 10,
                                                                                         s - 10,
                                                                                         s + 11,
                                                                                         s - 11,
                                                                                         s + 12,
                                                                                         s - 12};
    std::array<var, 8> input_state_var = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input),
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

    std::array<typename BlueprintFieldType::integral_type, 80> round_constant = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

    std::array<var, 16> input_words_var;
    for (int i = 0; i < 16; i++) {
        input_words_var[i] = var(0, 8 + i, false, var::column_type::public_input);
    }
    std::array<typename BlueprintFieldType::integral_type, 80> message_schedule_array;
    for (std::size_t i = 0; i < 16; i++) {
        message_schedule_array[i] = typename BlueprintFieldType::integral_type(public_input[8 + i].data);
    }
    for (std::size_t i = 16; i < 80; i++) {
        typename BlueprintFieldType::integral_type s0 =
            ((message_schedule_array[i - 15] >> 7) |
             ((message_schedule_array[i - 15] << (64 - 7)) &
              typename BlueprintFieldType::integral_type(
                  (typename BlueprintFieldType::value_type(2).pow(64) - 1).data))) ^
            ((message_schedule_array[i - 15] >> 18) |
             ((message_schedule_array[i - 15] << (64 - 18)) &
              typename BlueprintFieldType::integral_type(
                  (typename BlueprintFieldType::value_type(2).pow(64) - 1).data))) ^
            (message_schedule_array[i - 15] >> 3);
        typename BlueprintFieldType::integral_type s1 =
            ((message_schedule_array[i - 2] >> 17) |
             ((message_schedule_array[i - 2] << (64 - 17)) &
              typename BlueprintFieldType::integral_type(
                  (typename BlueprintFieldType::value_type(2).pow(64) - 1).data))) ^
            ((message_schedule_array[i - 2] >> 19) |
             ((message_schedule_array[i - 2] << (64 - 19)) &
              typename BlueprintFieldType::integral_type(
                  (typename BlueprintFieldType::value_type(2).pow(64) - 1).data))) ^
            (message_schedule_array[i - 2] >> 10);
        message_schedule_array[i] = (message_schedule_array[i - 16] + s0 + s1 + message_schedule_array[i - 7]) %
                                    typename curve_type::base_field_type::integral_type(
                                        typename curve_type::base_field_type::value_type(2).pow(64).data);
    }
    typename ArithmetizationType::field_type::integral_type a =
        typename ArithmetizationType::field_type::integral_type(public_input[0].data);
    typename ArithmetizationType::field_type::integral_type b =
        typename ArithmetizationType::field_type::integral_type(public_input[1].data);
    typename ArithmetizationType::field_type::integral_type c =
        typename ArithmetizationType::field_type::integral_type(public_input[2].data);
    typename ArithmetizationType::field_type::integral_type d =
        typename ArithmetizationType::field_type::integral_type(public_input[3].data);
    typename ArithmetizationType::field_type::integral_type e =
        typename ArithmetizationType::field_type::integral_type(public_input[4].data);
    typename ArithmetizationType::field_type::integral_type f =
        typename ArithmetizationType::field_type::integral_type(public_input[5].data);
    typename ArithmetizationType::field_type::integral_type g =
        typename ArithmetizationType::field_type::integral_type(public_input[6].data);
    typename ArithmetizationType::field_type::integral_type h =
        typename ArithmetizationType::field_type::integral_type(public_input[7].data);
    for (std::size_t i = 0; i < 80; i++) {
        typename BlueprintFieldType::integral_type S0 =
            ((a >> 2) | ((a << (64 - 2)) & typename BlueprintFieldType::integral_type(
                                               (typename BlueprintFieldType::value_type(2).pow(64) - 1).data))) ^
            ((a >> 13) | ((a << (64 - 13)) & typename BlueprintFieldType::integral_type(
                                                 (typename BlueprintFieldType::value_type(2).pow(64) - 1).data))) ^
            ((a >> 22) | ((a << (64 - 22)) & typename BlueprintFieldType::integral_type(
                                                 (typename BlueprintFieldType::value_type(2).pow(64) - 1).data)));
        typename BlueprintFieldType::integral_type S1 =
            ((e >> 6) | ((e << (64 - 6)) & typename BlueprintFieldType::integral_type(
                                               (typename BlueprintFieldType::value_type(2).pow(64) - 1).data))) ^
            ((e >> 11) | ((e << (64 - 11)) & typename BlueprintFieldType::integral_type(
                                                 (typename BlueprintFieldType::value_type(2).pow(64) - 1).data))) ^
            ((e >> 25) | ((e << (64 - 25)) & typename BlueprintFieldType::integral_type(
                                                 (typename BlueprintFieldType::value_type(2).pow(64) - 1).data)));
        typename BlueprintFieldType::integral_type maj = (a & b) ^ (a & c) ^ (b & c);
        typename BlueprintFieldType::integral_type ch = (e & f) ^ ((~e) & g);
        typename BlueprintFieldType::integral_type tmp1 = h + S1 + ch + round_constant[i] + message_schedule_array[i];
        typename BlueprintFieldType::integral_type tmp2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = (d + tmp1) % typename curve_type::base_field_type::integral_type(
                             typename curve_type::base_field_type::value_type(2).pow(64).data);
        d = c;
        c = b;
        b = a;
        a = (tmp1 + tmp2) % typename curve_type::base_field_type::integral_type(
                                typename curve_type::base_field_type::value_type(2).pow(64).data);
    }
    std::array<typename BlueprintFieldType::integral_type, 8> result_state = {
        (a + typename ArithmetizationType::field_type::integral_type(public_input[0].data)) %
            typename curve_type::base_field_type::integral_type(
                typename curve_type::base_field_type::value_type(2).pow(64).data),
        (b + typename ArithmetizationType::field_type::integral_type(public_input[1].data)) %
            typename curve_type::base_field_type::integral_type(
                typename curve_type::base_field_type::value_type(2).pow(64).data),
        (c + typename ArithmetizationType::field_type::integral_type(public_input[2].data)) %
            typename curve_type::base_field_type::integral_type(
                typename curve_type::base_field_type::value_type(2).pow(64).data),
        (d + typename ArithmetizationType::field_type::integral_type(public_input[3].data)) %
            typename curve_type::base_field_type::integral_type(
                typename curve_type::base_field_type::value_type(2).pow(64).data),
        (e + typename ArithmetizationType::field_type::integral_type(public_input[4].data)) %
            typename curve_type::base_field_type::integral_type(
                typename curve_type::base_field_type::value_type(2).pow(64).data),
        (f + typename ArithmetizationType::field_type::integral_type(public_input[5].data)) %
            typename curve_type::base_field_type::integral_type(
                typename curve_type::base_field_type::value_type(2).pow(64).data),
        (g + typename ArithmetizationType::field_type::integral_type(public_input[6].data)) %
            typename curve_type::base_field_type::integral_type(
                typename curve_type::base_field_type::value_type(2).pow(64).data),
        (h + typename ArithmetizationType::field_type::integral_type(public_input[7].data)) %
            typename curve_type::base_field_type::integral_type(
                typename curve_type::base_field_type::value_type(2).pow(64).data)};
    auto result_check = [result_state](AssignmentType &assignment, component_type::result_type &real_res) {
        for (std::size_t i = 0; i < 8; i++) {
            assert(result_state[i] == typename ArithmetizationType::field_type::integral_type(
                                          assignment.var_value(real_res.output_state[i]).data));
        }
    };
    typename component_type::params_type params = {input_state_var, input_words_var};
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

template<typename Hash, typename SignatureScheme>
void non_native_range(const state_type<Hash, SignatureScheme> &state) {
    using curve_type = nil::crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = zk::components::non_native_range<ArithmetizationType, curve_type, 0, 1, 2, 3, 4, 5, 6, 7, 8>;

    std::array<var, 4> input_var = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};

    typename component_type::params_type params = {input_var};

    std::vector<typename BlueprintFieldType::value_type> public_input = {455245345345345, 523553453454343,
                                                                         68753453534534689, 54355345344544};

    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

template<typename Hash, typename SignatureScheme>
void fixed_base_mul(const state_type<Hash, SignatureScheme> &state) {
    using curve_type = nil::crypto3::algebra::curves::pallas;
    using ed25519_type = nil::crypto3::algebra::curves::ed25519;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 6;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = zk::components::fixed_base_multiplication<ArithmetizationType, curve_type, ed25519_type, 0,
                                                                     1, 2, 3, 4, 5, 6, 7, 8>;

    var var_b = var(0, 0, false, var::column_type::public_input);

    ed25519_type::scalar_field_type::value_type b =
        nil::crypto3::algebra::random_element<ed25519_type::scalar_field_type>();

    typename component_type::params_type params = {{var_b}};

    ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type B =
        ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type::one();
    ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type P = b * B;
    ed25519_type::base_field_type::integral_type Px = ed25519_type::base_field_type::integral_type(P.X.data);
    ed25519_type::base_field_type::integral_type Py = ed25519_type::base_field_type::integral_type(P.Y.data);
    typename ed25519_type::base_field_type::integral_type base = 1;
    typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        typename curve_type::base_field_type::integral_type(b.data)};

    auto result_check = [Px, Py](AssignmentType &assignment, component_type::result_type &real_res) {
        typename ed25519_type::base_field_type::integral_type base = 1;
        typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;
        for (std::size_t i = 0; i < 4; i++) {
            assert(typename BlueprintFieldType::value_type((Px >> 66 * i) & mask) ==
                   assignment.var_value(real_res.output.x[i]));
            assert(typename BlueprintFieldType::value_type((Py >> 66 * i) & mask) ==
                   assignment.var_value(real_res.output.y[i]));
        }
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

template<typename Hash, typename SignatureScheme>
void complete_addidition(const state_type<Hash, SignatureScheme> &state) {
    using curve_type = nil::crypto3::algebra::curves::pallas;
    using ed25519_type = nil::crypto3::algebra::curves::ed25519;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 6;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type =
        zk::components::complete_addition<ArithmetizationType, curve_type, ed25519_type, 0, 1, 2, 3, 4, 5, 6, 7, 8>;

    std::array<var, 4> input_var_Xa = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};
    std::array<var, 4> input_var_Xb = {
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

    std::array<var, 4> input_var_Ya = {
        var(0, 8, false, var::column_type::public_input), var(0, 9, false, var::column_type::public_input),
        var(0, 10, false, var::column_type::public_input), var(0, 11, false, var::column_type::public_input)};
    std::array<var, 4> input_var_Yb = {
        var(0, 12, false, var::column_type::public_input), var(0, 13, false, var::column_type::public_input),
        var(0, 14, false, var::column_type::public_input), var(0, 15, false, var::column_type::public_input)};

    var b = var(0, 16, false, var::column_type::public_input);

    typename component_type::params_type params = {{input_var_Xa, input_var_Xb}, {input_var_Ya, input_var_Yb}};

    ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type T =
        nil::crypto3::algebra::random_element<
            ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>>();
    ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type R =
        nil::crypto3::algebra::random_element<
            ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>>();
    ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type P = T + R;
    ed25519_type::base_field_type::integral_type Tx = ed25519_type::base_field_type::integral_type(T.X.data);
    ed25519_type::base_field_type::integral_type Ty = ed25519_type::base_field_type::integral_type(T.Y.data);
    ed25519_type::base_field_type::integral_type Rx = ed25519_type::base_field_type::integral_type(R.X.data);
    ed25519_type::base_field_type::integral_type Ry = ed25519_type::base_field_type::integral_type(R.Y.data);
    ed25519_type::base_field_type::integral_type Px = ed25519_type::base_field_type::integral_type(P.X.data);
    ed25519_type::base_field_type::integral_type Py = ed25519_type::base_field_type::integral_type(P.Y.data);
    typename ed25519_type::base_field_type::integral_type base = 1;
    typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        Tx & mask, (Tx >> 66) & mask, (Tx >> 132) & mask, (Tx >> 198) & mask,
        Ty & mask, (Ty >> 66) & mask, (Ty >> 132) & mask, (Ty >> 198) & mask,
        Rx & mask, (Rx >> 66) & mask, (Rx >> 132) & mask, (Rx >> 198) & mask,
        Ry & mask, (Ry >> 66) & mask, (Ry >> 132) & mask, (Ry >> 198) & mask};

    auto result_check = [Px, Py](AssignmentType &assignment, component_type::result_type &real_res) {
        typename ed25519_type::base_field_type::integral_type base = 1;
        typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;
        for (std::size_t i = 0; i < 4; i++) {
            assert(typename BlueprintFieldType::value_type((Px >> 66 * i) & mask) ==
                   assignment.var_value(real_res.output.x[i]));
            assert(typename BlueprintFieldType::value_type((Py >> 66 * i) & mask) ==
                   assignment.var_value(real_res.output.y[i]));
        }
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

template<typename Hash, typename SignatureScheme>
void variable_base_multiplication(const state_type<Hash, SignatureScheme> &state) {
    using curve_type = nil::crypto3::algebra::curves::pallas;
    using ed25519_type = nil::crypto3::algebra::curves::ed25519;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 7;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = zk::components::variable_base_multiplication<ArithmetizationType, curve_type, ed25519_type,
                                                                        0, 1, 2, 3, 4, 5, 6, 7, 8>;

    std::array<var, 4> input_var_Xa = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};
    std::array<var, 4> input_var_Xb = {
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

    var b_var = var(0, 8, false, var::column_type::public_input);

    typename component_type::params_type params = {{input_var_Xa, input_var_Xb}, b_var};

    ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type T =
        nil::crypto3::algebra::random_element<
            ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>>();
    ed25519_type::scalar_field_type::value_type b =
        nil::crypto3::algebra::random_element<ed25519_type::scalar_field_type>();
    // ed25519_type::scalar_field_type::value_type b = 1;
    ed25519_type::base_field_type::integral_type integral_b = ed25519_type::base_field_type::integral_type(b.data);
    ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type P = b * T;
    ed25519_type::base_field_type::integral_type Tx = ed25519_type::base_field_type::integral_type(T.X.data);
    ed25519_type::base_field_type::integral_type Ty = ed25519_type::base_field_type::integral_type(T.Y.data);
    ed25519_type::base_field_type::integral_type Px = ed25519_type::base_field_type::integral_type(P.X.data);
    ed25519_type::base_field_type::integral_type Py = ed25519_type::base_field_type::integral_type(P.Y.data);
    typename ed25519_type::base_field_type::integral_type base = 1;
    typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        Tx & mask,         (Tx >> 66) & mask,  (Tx >> 132) & mask, (Tx >> 198) & mask, Ty & mask,
        (Ty >> 66) & mask, (Ty >> 132) & mask, (Ty >> 198) & mask, integral_b};

    auto result_check = [Px, Py](AssignmentType &assignment, component_type::result_type &real_res) {
        typename ed25519_type::base_field_type::integral_type base = 1;
        typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;
        for (std::size_t i = 0; i < 4; i++) {
            assert(typename BlueprintFieldType::value_type((Px >> 66 * i) & mask) ==
                   assignment.var_value(real_res.output.x[i]));
            assert(typename BlueprintFieldType::value_type((Py >> 66 * i) & mask) ==
                   assignment.var_value(real_res.output.y[i]));
        }
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

template<typename Hash, typename SignatureScheme>
void var_base_mul_per_bit(const state_type<Hash, SignatureScheme> &state) {
    using curve_type = nil::crypto3::algebra::curves::pallas;
    using ed25519_type = nil::crypto3::algebra::curves::ed25519;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 6;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type =
        zk::components::variable_base_multiplication_per_bit<ArithmetizationType, curve_type, ed25519_type, 0, 1, 2, 3,
                                                             4, 5, 6, 7, 8>;

    std::array<var, 4> input_var_Xa = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};
    std::array<var, 4> input_var_Xb = {
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

    std::array<var, 4> input_var_Ya = {
        var(0, 8, false, var::column_type::public_input), var(0, 9, false, var::column_type::public_input),
        var(0, 10, false, var::column_type::public_input), var(0, 11, false, var::column_type::public_input)};
    std::array<var, 4> input_var_Yb = {
        var(0, 12, false, var::column_type::public_input), var(0, 13, false, var::column_type::public_input),
        var(0, 14, false, var::column_type::public_input), var(0, 15, false, var::column_type::public_input)};

    var b = var(0, 16, false, var::column_type::public_input);

    typename component_type::params_type params = {{input_var_Xa, input_var_Xb}, {input_var_Ya, input_var_Yb}, b};

    ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type T =
        nil::crypto3::algebra::random_element<
            ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>>();
    ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type R = 2 * T;
    ed25519_type::scalar_field_type::value_type b_val = 1;
    ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type P =
        2 * R + b_val * T;

    ed25519_type::base_field_type::integral_type Tx = ed25519_type::base_field_type::integral_type(T.X.data);
    ed25519_type::base_field_type::integral_type Ty = ed25519_type::base_field_type::integral_type(T.Y.data);
    ed25519_type::base_field_type::integral_type Rx = ed25519_type::base_field_type::integral_type(R.X.data);
    ed25519_type::base_field_type::integral_type Ry = ed25519_type::base_field_type::integral_type(R.Y.data);
    ed25519_type::base_field_type::integral_type Px = ed25519_type::base_field_type::integral_type(P.X.data);
    ed25519_type::base_field_type::integral_type Py = ed25519_type::base_field_type::integral_type(P.Y.data);
    typename ed25519_type::base_field_type::integral_type base = 1;
    typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        Tx & mask,
        (Tx >> 66) & mask,
        (Tx >> 132) & mask,
        (Tx >> 198) & mask,
        Ty & mask,
        (Ty >> 66) & mask,
        (Ty >> 132) & mask,
        (Ty >> 198) & mask,
        Rx & mask,
        (Rx >> 66) & mask,
        (Rx >> 132) & mask,
        (Rx >> 198) & mask,
        Ry & mask,
        (Ry >> 66) & mask,
        (Ry >> 132) & mask,
        (Ry >> 198) & mask,
        typename ed25519_type::base_field_type::integral_type(b_val.data)};

    auto result_check = [Px, Py](AssignmentType &assignment, component_type::result_type &real_res) {
        typename ed25519_type::base_field_type::integral_type base = 1;
        typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;
        for (std::size_t i = 0; i < 4; i++) {
            assert(typename BlueprintFieldType::value_type((Px >> 66 * i) & mask) ==
                   assignment.var_value(real_res.output.x[i]));
            assert(typename BlueprintFieldType::value_type((Py >> 66 * i) & mask) ==
                   assignment.var_value(real_res.output.y[i]));
        }
    };
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

template<typename Hash, typename SignatureScheme>
nil::actor::future<> proof_gen(const state_type<Hash, SignatureScheme> &state) {
    return nil::actor::async([&] {
        sha256_process(state);
        non_native_demo(state);
        sha512_process(state);
        non_native_range(state);
        fixed_base_mul(state);
        complete_addidition(state);
        variable_base_multiplication(state);
        var_base_mul_per_bit(state);
        std::cout << "All process ends" << std::endl;
    });
}

struct prover {
    typedef nil::crypto3::hashes::sha2<256> hash_type;
    typedef nil::crypto3::algebra::curves::ed25519 signature_curve_type;
    typedef typename signature_curve_type::template g1_type<> group_type;
    typedef nil::crypto3::pubkey::eddsa<group_type, nil::crypto3::pubkey::eddsa_type::basic, void>
        signature_scheme_type;
    typedef typename nil::crypto3::pubkey::public_key<signature_scheme_type>::signature_type signature_type;

    prover(boost::application::context &context) : context_(context) {
    }

    int operator()() {
        BOOST_APPLICATION_FEATURE_SELECT
        std::string string = context_.find<nil::proof::aspects::proof>()->input_string();

        state_type<hash_type, signature_scheme_type> state;
        boost::json::monotonic_resource mr;
        state = boost::json::value_to<state_type<hash_type, signature_scheme_type>>(boost::json::parse(string, &mr));

        (void)nil::actor::engine().when_started().then(
            [&state]() { return proof_gen<hash_type, signature_scheme_type>(state); });
        auto exit_code = nil::actor::engine().run();
        std::cout << exit_code << std::endl;
        nil::actor::smp::cleanup();

        return 0;
    }

    boost::application::context &context_;
};

bool setup(boost::application::context &context) {
    return false;
}

int main(int argc, char *argv[]) {
    boost::system::error_code ec;
    /*<<Create a global context application aspect pool>>*/
    boost::application::context ctx;

    boost::application::auto_handler<prover> app(ctx);

    if (!insert_aspects(ctx, app, boost::make_shared<nil::proof::aspects::args>(argc, argv))) {
        std::cout << "[E] Application aspects configuration failed!" << std::endl;
        return 1;
    }
    if (configure_aspects(ctx, app)) {
        std::cout << "[I] Setup changed the current configuration." << std::endl;
    }
    // my server instantiation
    int result = boost::application::launch<boost::application::common>(app, ctx, ec);

    if (ec) {
        std::cout << "[E] " << ec.message() << " <" << ec.value() << "> " << std::endl;
    }

    return result;
}