//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//

#ifndef ACTOR_TEST_PLONK_COMPONENT_HPP
#define ACTOR_TEST_PLONK_COMPONENT_HPP

#include <fstream>
#include <random>

#include <nil/actor/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/params.hpp>

#include <nil/actor/zk/blueprint/plonk.hpp>
#include <nil/actor/zk/assignment/plonk.hpp>
#include <nil/actor/zk/algorithms/allocate.hpp>
#include <nil/actor/zk/algorithms/generate_circuit.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>
#include <nil/crypto3/marshalling/zk/types/placeholder/proof.hpp>

namespace nil {
    namespace actor {
        template<typename TIter>
        void print_hex_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end, bool endl) {
            os << "0x" << std::hex;
            for (TIter it = iter_begin; it != iter_end; it++) {
                os << std::setfill('0') << std::setw(2) << std::right << int(*it);
            }
            os << std::dec;
            if (endl) {
                os << std::endl;
            }
        }

        template<typename Endianness, typename Proof>
        void proof_print(Proof &proof) {
            using namespace nil::crypto3::marshalling;

            using TTypeBase = nil::marshalling::field_type<Endianness>;
            using proof_marshalling_type = zk::snark::placeholder_proof<TTypeBase, Proof>;
            auto filled_placeholder_proof = crypto3::marshalling::types::fill_placeholder_proof<Endianness, Proof>(
                    proof);

            std::vector<std::uint8_t> cv;
            cv.resize(filled_placeholder_proof.length(), 0x00);
            auto write_iter = cv.begin();
            nil::marshalling::status_type status = filled_placeholder_proof.write(write_iter, cv.size());
            std::ofstream out;
            out.open("placeholder_proof.data");
            print_hex_byteblob(out, cv.cbegin(), cv.cend(), false);
        }

        inline std::vector<std::size_t> generate_random_step_list(const std::size_t r, const int max_step) {
            using dist_type = std::uniform_int_distribution<int>;
            static std::random_device random_engine;

            std::vector<std::size_t> step_list;
            std::size_t steps_sum = 0;
            while (steps_sum != r) {
                if (r - steps_sum <= max_step) {
                    while (r - steps_sum != 1) {
                        step_list.emplace_back(r - steps_sum - 1);
                        steps_sum += step_list.back();
                    }
                    step_list.emplace_back(1);
                    steps_sum += step_list.back();
                } else {
                    step_list.emplace_back(dist_type(1, max_step)(random_engine));
                    steps_sum += step_list.back();
                }
            }
            return step_list;
        }

        template<typename fri_type, typename FieldType>
        typename fri_type::params_type create_fri_params(std::size_t degree_log, const int max_step = 1) {
            typename fri_type::params_type params;
            math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

            constexpr std::size_t expand_factor = 0;
            std::size_t r = degree_log - 1;

            std::vector<std::shared_ptr<crypto3::math::evaluation_domain<FieldType>>> domain_set =
                    crypto3::math::calculate_domain_set<FieldType>(degree_log + expand_factor, r);

            params.r = r;
            params.D = domain_set;
            params.max_degree = (1 << degree_log) - 1;
            params.step_list = generate_random_step_list(r, max_step);

            return params;
        }

        template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename Hash,
                std::size_t Lambda, typename FunctorResultCheck, typename PublicInput,
                typename std::enable_if<
                        std::is_same<typename BlueprintFieldType::value_type,
                                typename std::iterator_traits<typename PublicInput::iterator>::value_type>::value,
                        bool>::type = true>
        auto prepare_component(typename ComponentType::params_type params, const PublicInput &public_input,
                               const FunctorResultCheck &result_check) {

            using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
            using component_type = ComponentType;

            zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> desc;

            zk::blueprint<ArithmetizationType> bp(desc);
            zk::blueprint_private_assignment_table<ArithmetizationType> private_assignment(desc);
            zk::blueprint_public_assignment_table<ArithmetizationType> public_assignment(desc);
            zk::blueprint_assignment_table<ArithmetizationType> assignment_bp(private_assignment, public_assignment);

            std::size_t start_row = zk::components::allocate<component_type>(bp);
            if (public_input.size() > component_type::rows_amount) {
                bp.allocate_rows(public_input.size() - component_type::rows_amount);
            }

            for (std::size_t i = 0; i < public_input.size(); i++) {
                auto allocated_pi = assignment_bp.allocate_public_input(public_input[i]);
            }

            zk::components::generate_circuit<component_type>(bp, public_assignment, params, start_row);
            typename component_type::result_type component_result =
                    component_type::generate_assignments(assignment_bp, params, start_row);

            result_check(assignment_bp, component_result);

            assignment_bp.padding();
            std::cout << "Usable rows: " << desc.usable_rows_amount << std::endl;
            std::cout << "Padded rows: " << desc.rows_amount << std::endl;

            zk::snark::plonk_assignment_table<BlueprintFieldType, ArithmetizationParams> assignments(private_assignment,
                                                                                                     public_assignment);

            using placeholder_params =
                    zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, Hash, Hash, Lambda>;
            using types = zk::snark::detail::placeholder_policy<BlueprintFieldType, placeholder_params>;

            using fri_type =
                    typename zk::commitments::fri<BlueprintFieldType, typename placeholder_params::merkle_hash_type,
                            typename placeholder_params::transcript_hash_type, 2, 1>;

            std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));

            typename fri_type::params_type fri_params = create_fri_params<fri_type, BlueprintFieldType>(table_rows_log);

            std::size_t permutation_size = desc.witness_columns + desc.public_input_columns + desc.constant_columns;

            typename zk::snark::placeholder_public_preprocessor<
                    BlueprintFieldType, placeholder_params>::preprocessed_data_type public_preprocessed_data =
                    zk::snark::placeholder_public_preprocessor<BlueprintFieldType, placeholder_params>::process(
                            bp, public_assignment, desc, fri_params, permutation_size).get();
            typename zk::snark::placeholder_private_preprocessor<
                    BlueprintFieldType, placeholder_params>::preprocessed_data_type private_preprocessed_data =
                    zk::snark::placeholder_private_preprocessor<BlueprintFieldType, placeholder_params>::process(
                            bp, private_assignment, desc, fri_params).get();

            return std::make_tuple(desc, bp, fri_params, assignments, public_preprocessed_data,
                                   private_preprocessed_data);
        }

        template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename Hash,
                std::size_t Lambda, typename PublicInput, typename FunctorResultCheck>
        typename std::enable_if<
                std::is_same<typename BlueprintFieldType::value_type,
                        typename std::iterator_traits<typename PublicInput::iterator>::value_type>::value>::type
        test_component(typename ComponentType::params_type params, const PublicInput &public_input,
                       FunctorResultCheck result_check) {
            using placeholder_params =
                    zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, Hash, Hash, Lambda>;

            auto [desc, bp, fri_params, assignments, public_preprocessed_data, private_preprocessed_data] =
                    prepare_component<ComponentType, BlueprintFieldType, ArithmetizationParams, Hash, Lambda,
                            FunctorResultCheck>(params, public_input, result_check);

            auto proof = zk::snark::placeholder_prover<BlueprintFieldType, placeholder_params>::process(
                    public_preprocessed_data, private_preprocessed_data, desc, bp, assignments, fri_params);

            bool verifier_res = zk::snark::placeholder_verifier<BlueprintFieldType, placeholder_params>::process(
                    public_preprocessed_data, proof, bp, fri_params);

            proof_print<nil::marshalling::option::big_endian>(proof);
            std::cout << "verifier_res=" << verifier_res << std::endl;
            assert(verifier_res == true);
        }

        template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename Hash,
                std::size_t Lambda, typename PublicInput, typename FunctorResultCheck,
                typename std::enable_if<
                        std::is_same<typename BlueprintFieldType::value_type,
                                typename std::iterator_traits<typename PublicInput::iterator>::value_type>::value,
                        bool>::type = true>
        auto create_component_proof(typename ComponentType::params_type params, const PublicInput &public_input,
                                    const FunctorResultCheck &result_check) {

            using placeholder_params =
                    zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, Hash, Hash, Lambda>;

            auto [desc, bp, fri_params, assignments, public_preprocessed_data, private_preprocessed_data] =
                    prepare_component<ComponentType, BlueprintFieldType, ArithmetizationParams, Hash, Lambda>(
                            params, public_input, result_check);

            auto proof = zk::snark::placeholder_prover<BlueprintFieldType, placeholder_params>::process(
                    public_preprocessed_data, private_preprocessed_data, desc, bp, assignments, fri_params);

            bool verifier_res = zk::snark::placeholder_verifier<BlueprintFieldType, placeholder_params>::process(
                    public_preprocessed_data, proof, bp, fri_params);
            proof_print<nil::marshalling::option::big_endian>(proof);
            std::cout << "verifier_res=" << verifier_res << std::endl;
            assert(verifier_res == true);
            return std::make_tuple(proof, fri_params, public_preprocessed_data, bp);
        }
    }    // namespace actor
}    // namespace nil

#endif    // ACTOR_TEST_PLONK_COMPONENT_HPP
