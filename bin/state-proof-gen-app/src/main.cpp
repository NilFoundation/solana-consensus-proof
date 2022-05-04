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
#include <boost/circular_buffer.hpp>
#include <boost/optional.hpp>

//#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
//#include <nil/crypto3/algebra/random_element.hpp>
//#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
//#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
//#include <nil/crypto3/algebra/curves/params/multiexp/alt_bn128.hpp>
//#include <nil/crypto3/algebra/curves/params/wnaf/alt_bn128.hpp>
//
//#include <nil/crypto3/zk/blueprint/plonk.hpp>
//#include <nil/crypto3/zk/assignment/plonk.hpp>
//#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/unified_addition.hpp>
//#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/variable_base_endo_scalar_mul_15_wires.hpp>
//#include <nil/crypto3/zk/components/hashes/poseidon/plonk/poseidon_15_wires.hpp>
//
//#include <nil/crypto3/hash/algorithm/hash.hpp>
//#include <nil/crypto3/hash/keccak.hpp>
//#include <nil/crypto3/hash/sha2.hpp>
//
//#include <nil/crypto3/pubkey/algorithm/sign.hpp>
//#include <nil/crypto3/pubkey/eddsa.hpp>
//
//#include <nil/crypto3/zk/commitments/type_traits.hpp>
//#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
//#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
//#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
//#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
//#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
//
//#include <nil/marshalling/endianness.hpp>
//#include <nil/crypto3/marshalling/zk/types/placeholder/proof.hpp>

#include <nil/actor/core/app_template.hh>
#include <nil/actor/core/reactor.hh>
#include <nil/actor/core/scollectd.hh>
#include <nil/actor/core/metrics_api.hh>
#include <nil/actor/core/print.hh>
#include <nil/actor/detail/log.hh>
#include <nil/actor/detail/log-cli.hh>

#include <nil/actor/core/sleep.hh>
#include <nil/actor/core/when_all.hh>
#include <boost/range/irange.hpp>
#include <nil/actor/core/thread.hh>
#include <nil/actor/core/with_scheduling_group.hh>

#include <fstream>

#include <nil/proof/aspects/actor.hpp>
#include <nil/proof/aspects/args.hpp>
#include <nil/proof/aspects/path.hpp>
#include <nil/proof/aspects/configuration.hpp>
#include <nil/proof/detail/configurable.hpp>

using namespace nil;
// using namespace nil::crypto3;
// using namespace nil::marshalling;
//

// nil::actor::future<> say_hello() {
//     nil::actor::print("Hello, World; from simple_actor located on core %u .\n", nil::actor::engine().cpu_id());
//     // Simulate long-running job
//     return nil::actor::sleep(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::milliseconds(500)));
// };

nil::actor::future<> say_hello() {
    nil::actor::print("Hello, World; from simple_actor located on core %u .\n", nil::actor::engine().cpu_id());
    // Simulate long-running job
    return nil::actor::make_ready_future();
};

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

    boost::shared_ptr<proof::aspects::path> path_aspect = boost::make_shared<proof::aspects::path>();

    ctx.insert<proof::aspects::path>(path_aspect);
    ctx.insert<proof::aspects::configuration>(boost::make_shared<proof::aspects::configuration>(path_aspect));
    ctx.insert<proof::aspects::actor>(boost::make_shared<proof::aspects::actor>(path_aspect));

    return true;
}

template<typename Application>
inline bool configure_aspects(boost::application::context &ctx, Application &app) {
//    typedef module::configurable<boost::program_options::variables_map, boost::program_options::options_description,
//                                 boost::program_options::options_description>
//        configurable_aspect_type;
    typedef nil::proof::detail::configurable<dbms::plugin::variables_map, dbms::plugin::cli_options_description,
                     dbms::plugin::cfg_options_description> configurable_aspect_type;

    boost::strict_lock<boost::application::aspect_map> guard(ctx);
    boost::shared_ptr<proof::aspects::args> args = ctx.find<proof::aspects::args>(guard);
    boost::shared_ptr<proof::aspects::configuration> cfg = ctx.find<proof::aspects::configuration>(guard);

//    dbms::plugin::cfg_options_description x = cfg->cfg();
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

class myapp {
public:
    myapp(boost::application::context &context) : context_(context) {
    }

    int operator()() {
        //        BOOST_APPLICATION_FEATURE_SELECT
        //        actor_aspect actor_conf;
        //
        //        boost::shared_ptr<boost::application::args> myargs = context_.find<boost::application::args>();
        //        auto ac = myargs->argc();
        //        auto av = myargs->argv();
        //
        //        boost::program_options::variables_map configuration;
        //        boost::program_options::options_description _opts;
        //
        //        actor_conf.set_options(_opts);
        //        try {
        //            boost::program_options::store(
        //                boost::program_options::command_line_parser(ac, av).options(_opts).run(),
        //                configuration);
        //        } catch (boost::program_options::error &e) {
        //            fmt::print("error: {}\n\nTry --help.\n", e.what());
        //            return 2;
        //        }
        //
        //        std::cout << "Here" << std::endl;
        //        actor_conf.initialize(configuration);
        //
        //        try {
        //            nil::actor::smp::configure(configuration, reactor_config_from_app_config(actor_conf._cfg));
        //        } catch (...) {
        //            std::cerr << "Could not initialize actor: " << std::current_exception() << std::endl;
        //            return 1;
        //        }
        //
        //        (void) nil::actor::engine().when_started().then(std::move(say_hello)).then_wrapped(
        //            [](auto &&f) {
        //                try {
        //                    f.get();
        //                } catch (std::exception &ex) {
        //                    std::cout << "program failed with uncaught exception: " << ex.what() << "\n";
        //                    nil::actor::engine().exit(1);
        //                }
        //            });
        //        auto exit_code = nil::actor::engine().run();
        //        std::cout << exit_code << std::endl;
        //
        //        nil::actor::smp::cleanup();
        return 0;
    }

    boost::application::context &context_;
};

bool setup(boost::application::context &context) {
    return false;
}

// main
int main(int argc, char *argv[]) {

    boost::system::error_code ec;
    /*<<Create a global context application aspect pool>>*/
    boost::application::context ctx;

    boost::application::auto_handler<myapp> app(ctx);

    if (!insert_aspects(ctx, app, boost::make_shared<nil::proof::aspects::args>(argc, argv))) {
        std::cout << "[E] Application aspects configuration failed!" << std::endl;
        return 1;
    }
    std::cout << "Here" << std::endl;
    if (configure_aspects(ctx, app)) {
        std::cout << "[I] Setup changed the current configuration." << std::endl;
    }
        std::cout << "Here1" << std::endl;
    // my server instantiation
//    int result = boost::application::launch<boost::application::common>(app, ctx, ec);
//
//    if (ec) {
//        std::cout << "[E] " << ec.message() << " <" << ec.value() << "> " << std::endl;
//    }

    return 0;
}