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
//#include <nil/crypto3/zk/snark/systems/plonk/redshift/preprocessor.hpp>
//#include <nil/crypto3/zk/snark/systems/plonk/redshift/prover.hpp>
//#include <nil/crypto3/zk/snark/systems/plonk/redshift/verifier.hpp>
//#include <nil/crypto3/zk/snark/systems/plonk/redshift/params.hpp>
//
//#include <nil/marshalling/endianness.hpp>
//#include <nil/crypto3/marshalling/zk/types/redshift/proof.hpp>

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

//using namespace nil;
//using namespace nil::crypto3;
//using namespace nil::marshalling;
//

// my functor application
struct config {
    nil::actor::sstring name = "App";
    nil::actor::sstring description = "";
    std::chrono::duration<double> default_task_quota = std::chrono::microseconds(500);
    bool auto_handle_sigint_sigterm = true;

    config() {
    }
};

static nil::actor::reactor_config reactor_config_from_app_config(config cfg) {
    nil::actor::reactor_config ret;
    ret.auto_handle_sigint_sigterm = cfg.auto_handle_sigint_sigterm;
    ret.task_quota = cfg.default_task_quota;
    return ret;
};

//nil::actor::future<> say_hello() {
//    nil::actor::print("Hello, World; from simple_actor located on core %u .\n", nil::actor::engine().cpu_id());
//    // Simulate long-running job
//    return nil::actor::sleep(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::milliseconds(500)));
//};

nil::actor::future<> say_hello()  {
    nil::actor::print("Hello, World; from simple_actor located on core %u .\n", nil::actor::engine().cpu_id());
    // Simulate long-running job
    return nil::actor::make_ready_future();
};

template<typename Func, typename Duration>
nil::actor::future<> compute_intensive_task(Duration duration, unsigned &counter, Func func) {
    auto end = std::chrono::steady_clock::now() + duration;
    while (std::chrono::steady_clock::now() < end) {
        func();
    }
    ++counter;
    return nil::actor::make_ready_future<>();
}

nil::actor::future<> heavy_task(unsigned &counter) {
    return compute_intensive_task(std::chrono::milliseconds(100), counter, [] {
        static thread_local double x = 1;
        x = std::exp(x) / 3;
    });
}

nil::actor::future<> light_task(unsigned &counter) {
    return compute_intensive_task(std::chrono::milliseconds(10), counter, [] {
        static thread_local double x = 0.1;
        x = std::log(x + 1);
    });
}

nil::actor::future<> medium_task(unsigned &counter) {
    return compute_intensive_task(std::chrono::milliseconds(1), counter, [] {
        static thread_local double x = 0.1;
        x = std::cos(x);
    });
}

nil::actor::future<> example() {
    auto sg2 = nil::actor::create_scheduling_group("sg20", 20).get0();
    return nil::actor::async([task = std::move(say_hello), sg2]() mutable {
            nil::actor::parallel_for_each(boost::irange(0u, 3u), [task, sg2](unsigned i) mutable {
                return nil::actor::with_scheduling_group(sg2, [task] { return say_hello(); });
            }).get();
            nil::actor::thread::maybe_yield();
    });
}

struct actor_aspect {

    void initialize(boost::program_options::variables_map &configuration) {
        if (configuration.count("help")) {
            if (!_cfg.description.empty()) {
                std::cout << _cfg.description << "\n";
            }
//            std::cout << _opts << "\n";
//            return 1;
            exit(1);
        }
        if (configuration["help-loggers"].as<bool>()) {
            nil::actor::log_cli::print_available_loggers(std::cout);
//            return 1;
            exit(1);
        }

        try {
            boost::program_options::notify(configuration);
        } catch (const boost::program_options::required_option &ex) {
            std::cout << ex.what() << std::endl;
            //            return 1;
            exit(1);
        }

        // Needs to be before `smp::configure()`.
        try {
            apply_logging_settings(nil::actor::log_cli::extract_settings(configuration));
        } catch (const std::runtime_error &exn) {
            std::cout << "logging configuration error: " << exn.what() << '\n';
            //            return 1;
            exit(1);
        }

//        configuration.emplace("argv0", boost::program_options::variable_value(std::string(av[0]), false));
    }

    void set_options(boost::program_options::options_description &cli) {
        boost::program_options::options_description _opts;
        boost::program_options::options_description _opts_conf_file;

        //configure
        _opts.add_options()("help,h", "show help message");

        nil::actor::smp::register_network_stacks();
        _opts_conf_file.add(nil::actor::reactor::get_options_description(reactor_config_from_app_config(_cfg)));
        _opts_conf_file.add(nil::actor::metrics::get_options_description());
        _opts_conf_file.add(nil::actor::smp::get_options_description());
        _opts_conf_file.add(nil::actor::scollectd::get_options_description());
        _opts_conf_file.add(nil::actor::log_cli::get_options_description());

        _opts.add(_opts_conf_file);

        cli.add(_opts);
    }

    config _cfg;
};

class myapp {
public:
    myapp(boost::application::context &context) : context_(context) {
    }

    int operator()() {
        BOOST_APPLICATION_FEATURE_SELECT
        actor_aspect actor_conf;

        boost::shared_ptr<boost::application::args> myargs = context_.find<boost::application::args>();
        auto ac = myargs->argc();
        auto av = myargs->argv();

        boost::program_options::variables_map configuration;
        boost::program_options::options_description _opts;

        actor_conf.set_options(_opts);
        try {
            boost::program_options::store(
                boost::program_options::command_line_parser(ac, av).options(_opts).run(),
                configuration);
        } catch (boost::program_options::error &e) {
            fmt::print("error: {}\n\nTry --help.\n", e.what());
            return 2;
        }

        std::cout << "Here" << std::endl;
        actor_conf.initialize(configuration);

        try {
            nil::actor::smp::configure(configuration, reactor_config_from_app_config(actor_conf._cfg));
        } catch (...) {
            std::cerr << "Could not initialize actor: " << std::current_exception() << std::endl;
            return 1;
        }

        (void) nil::actor::engine().when_started().then(std::move(say_hello)).then_wrapped(
                [](auto &&f) {
                    try {
                        f.get();
                    } catch (std::exception &ex) {
                        std::cout << "program failed with uncaught exception: " << ex.what() << "\n";
                        nil::actor::engine().exit(1);
                    }
                });
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

// main

int main(int argc, char *argv[]) {

    boost::system::error_code ec;
    /*<<Create a global context application aspect pool>>*/
    boost::application::context app_context;

    boost::application::auto_handler<myapp> app(app_context);

    app_context.insert<boost::application::path>(boost::make_shared<boost::application::path>());

    app_context.insert<boost::application::args>(boost::make_shared<boost::application::args>(argc, argv));

    if (setup(app_context)) {
        std::cout << "[I] Setup changed the current configuration." << std::endl;
        return 0;
    }

    // my server instantiation
    int result = boost::application::launch<boost::application::common>(app, app_context, ec);

    if (ec) {
        std::cout << "[E] " << ec.message() << " <" << ec.value() << "> " << std::endl;
    }

    return 0;
}