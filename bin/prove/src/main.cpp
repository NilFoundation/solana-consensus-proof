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
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/alt_bn128.hpp>

#include <nil/crypto3/zk/components/blueprint.hpp>
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

int main(int argc, char *argv[]) {

    typedef hashes::sha2<256> hash_type;
    typedef algebra::curves::alt_bn128<254> system_curve_type;
    typedef algebra::curves::curve25519 signature_curve_type;

#ifndef __EMSCRIPTEN__
    boost::program_options::options_description options("Solana 'Light-Client' State Proof Generator");
    // clang-format off
    options.add_options()("help,h", "Display help message")
    ("version,v", "Display version")
    ("generate", "Generate");
    // clang-format on

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(options).run(), vm);
    boost::program_options::notify(vm);

    if (vm.count("help") || argc < 2) {
        std::cout << options << std::endl;
        return 0;
    }
#else

#endif

    using TBlueprintField = typename system_curve_type::base_field_type;
    constexpr std::size_t WiresAmount = 5;
    using TArithmetization = zk::snark::plonk_constraint_system<TBlueprintField, WiresAmount>;

    zk::components::blueprint<TArithmetization> bp;
    zk::components::element_g1_variable_base_scalar_mul_plonk<TBlueprintField, system_curve_type> scalar_mul(bp);

    zk::snark::redshift_preprocessor<typename curve_type::base_field_type, 5, 2> preprocess;

    // auto preprocessed_data = preprocess::process(cs, assignments);
    zk::snark::redshift_prover<typename curve_type::base_field_type, 5, 2, 2, 2> prove;

    return 0;
}