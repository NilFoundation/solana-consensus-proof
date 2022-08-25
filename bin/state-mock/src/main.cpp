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

#include <array>
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

#include <nil/crypto3/algebra/curves/ed25519.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/pubkey/algorithm/sign.hpp>
#include <nil/crypto3/pubkey/eddsa.hpp>

#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/marshalling/status_type.hpp>

#include <nil/crypto3/marshalling/multiprecision/types/integral.hpp>

#include <nil/crypto3/codec/algorithm/encode.hpp>
#include <nil/crypto3/codec/algorithm/decode.hpp>
#include <nil/crypto3/codec/base.hpp>
#include <nil/crypto3/codec/hex.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>

using namespace nil::crypto3;
using namespace nil::marshalling;

template<typename Hash, typename CurveType>
struct signature_t {
    typedef typename CurveType::base_field_type::integral_type integral_type;
    typedef typename CurveType::scalar_field_type::value_type value_type;
    std::array<integral_type, 2> points;
    value_type scalar;
};

template<typename Hash, typename CurveType>
struct vote_state {
    typedef Hash hash_type;
    typedef typename Hash::digest_type digest_type;
    typedef typename CurveType::base_field_type::integral_type integral_type;
    signature_t<Hash, CurveType> signature;
    std::array<integral_type, 2> pubkey;

    std::size_t weight;
};

template<typename Hash, typename CurveType>
struct block_data {
    typedef Hash hash_type;
    typedef typename Hash::digest_type digest_type;

    std::size_t block_number;
    digest_type bank_hash;
    digest_type previous_bank_hash;
    std::uint32_t timestamp;
};

template<typename Hash, typename CurveType>
struct state_type {
    typedef Hash hash_type;
    typedef typename Hash::digest_type digest_type;
    std::size_t confirmed;
    std::size_t new_confirmed;
    digest_type bank_hash;
    std::vector<block_data<Hash, CurveType>> repl_data;
    std::vector<std::vector<vote_state<Hash, CurveType>>> votes;
};

template<typename Hash, typename CurveType>
void tag_invoke(boost::json::value_from_tag, boost::json::value &jv, block_data<Hash, CurveType> const &c) {
    std::string bank_hash = nil::crypto3::decode<nil::crypto3::codec::hex<nil::crypto3::codec::mode::lower>>(
            std::to_string(c.bank_hash));
    std::string previous_bank_hash = nil::crypto3::decode<nil::crypto3::codec::hex<nil::crypto3::codec::mode::lower>>(
            std::to_string(c.previous_bank_hash));

    jv = {{"block_number",       c.block_number},
          {"bank_hash",          (std::string) nil::crypto3::encode<nil::crypto3::codec::base<58>>(bank_hash)},
          {"previous_bank_hash", (std::string) nil::crypto3::encode<nil::crypto3::codec::base<58>>(previous_bank_hash)},
          {"timestamp",          c.timestamp}};
}

template<typename Hash, typename CurveType>
void tag_invoke(boost::json::value_from_tag, boost::json::value &jv, vote_state<Hash, CurveType> const &c) {
    nil::marshalling::status_type status;

    std::string signature;
    std::vector<uint8_t> br = nil::marshalling::pack<nil::marshalling::option::big_endian>(c.signature.points, status);
    std::vector<uint8_t> bytes_res = nil::marshalling::pack<nil::marshalling::option::big_endian>(c.signature.scalar,
                                                                                                  status);
    br.insert(br.end(), bytes_res.begin(), bytes_res.end());
    nil::crypto3::encode<nil::crypto3::codec::base<58>>(br.begin(), br.end(), std::back_inserter(signature));

    std::string pubkey;
    std::vector<uint8_t> pubkey_blob = nil::marshalling::pack<nil::marshalling::option::big_endian>(c.pubkey, status);
    nil::crypto3::encode<nil::crypto3::codec::base<58>>(pubkey_blob.begin(), pubkey_blob.end(),
                                                        std::back_inserter(pubkey));

    jv = {{"signature", signature},
          {"pubkey",    pubkey},
          {"weight",    c.weight}};
}

template<typename Hash, typename CurveType>
void tag_invoke(boost::json::value_from_tag, boost::json::value &jv, state_type<Hash, CurveType> const &c) {
    std::string bank_hash = nil::crypto3::decode<nil::crypto3::codec::hex<nil::crypto3::codec::mode::lower>>(
            std::to_string(c.bank_hash));
    jv = {
            {"confirmed",     c.confirmed},
            {"new_confirmed", c.new_confirmed},
            {"repl_data",     c.repl_data},
            {"bank_hash",     (std::string) nil::crypto3::encode<nil::crypto3::codec::base<58>>(c.bank_hash)},
            {"votes",         c.votes}
    };
}

template<typename Hash, typename CurveType>
vote_state<Hash, CurveType>
tag_invoke(boost::json::value_to_tag<vote_state<Hash, CurveType>>, const boost::json::value &jv) {
    auto &o = jv.as_object();
    return {
//            .signature =
//            [&](const boost::json::value &v) {
//            }(o.at("signature")),
//            .pubkey =
//            [&](const boost::json::value &v) {
//            }(o.at("pubkey")),
            .weight = boost::json::value_to<std::size_t>(o.at("weight"))};
}

template<typename Hash, typename CurveType>
block_data<Hash, CurveType>
tag_invoke(boost::json::value_to_tag<block_data<Hash, CurveType>>, const boost::json::value &jv) {
    auto &o = jv.as_object();

    return {
            .block_number = boost::json::value_to<std::size_t>(o.at("block_number")),
            .bank_hash =
            [&](const boost::json::value &v) {
                typename Hash::digest_type ret;
                nil::crypto3::decode<nil::crypto3::codec::base<58>>(
                        boost::json::value_to<std::string>(v), ret.begin());
                return ret;
            }(o.at("bank_hash")),
            .previous_bank_hash =
            [&](const boost::json::value &v) {
                typename Hash::digest_type ret;
                nil::crypto3::decode<nil::crypto3::codec::base<58>>(
                        boost::json::value_to<std::string>(v), ret.begin());

                return ret;
            }(o.at("previous_bank_hash")),
            .timestamp = boost::json::value_to<std::uint32_t>(o.at("timestamp")),
    };
}

template<typename Hash, typename CurveType>
state_type<Hash, CurveType> tag_invoke(boost::json::value_to_tag<state_type<Hash, CurveType>>,
                                       const boost::json::value &jv) {
    auto &o = jv.as_object();
    return {.confirmed = boost::json::value_to<std::size_t>(o.at("confirmed")),
            .new_confirmed = boost::json::value_to<std::size_t>(o.at("new_confirmed")),
            .repl_data =
            [&](const boost::json::value &arr) {
                std::vector<block_data<Hash, CurveType>> ret;
                for (const boost::json::value &val: arr.as_array()) {
                    ret.emplace_back(boost::json::value_to<block_data<Hash, CurveType>>(val));
                }
                return ret;
            }(o.at("repl_data"))
    };
}

void pretty_print(std::ostream &os, boost::json::value const &jv, std::string *indent = nullptr) {
    std::string indent_;
    if (!indent) {
        indent = &indent_;
    }
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

template<typename ed25519_type>
typename ed25519_type::scalar_field_type::value_type sha512(typename ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type R,
                                                            typename ed25519_type::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type pk, std::array<typename ed25519_type::base_field_type::integral_type, 4> M) {
    std::array<typename ed25519_type::base_field_type::integral_type, 80>
            round_constant = {
            0x428a2f98d728ae22_cppui64, 0x7137449123ef65cd_cppui64, 0xb5c0fbcfec4d3b2f_cppui64, 0xe9b5dba58189dbbc_cppui64,
            0x3956c25bf348b538_cppui64, 0x59f111f1b605d019_cppui64, 0x923f82a4af194f9b_cppui64, 0xab1c5ed5da6d8118_cppui64,
            0xd807aa98a3030242_cppui64, 0x12835b0145706fbe_cppui64, 0x243185be4ee4b28c_cppui64, 0x550c7dc3d5ffb4e2_cppui64,
            0x72be5d74f27b896f_cppui64, 0x80deb1fe3b1696b1_cppui64, 0x9bdc06a725c71235_cppui64, 0xc19bf174cf692694_cppui64,
            0xe49b69c19ef14ad2_cppui64, 0xefbe4786384f25e3_cppui64, 0x0fc19dc68b8cd5b5_cppui64, 0x240ca1cc77ac9c65_cppui64,
            0x2de92c6f592b0275_cppui64, 0x4a7484aa6ea6e483_cppui64, 0x5cb0a9dcbd41fbd4_cppui64, 0x76f988da831153b5_cppui64,
            0x983e5152ee66dfab_cppui64, 0xa831c66d2db43210_cppui64, 0xb00327c898fb213f_cppui64, 0xbf597fc7beef0ee4_cppui64,
            0xc6e00bf33da88fc2_cppui64, 0xd5a79147930aa725_cppui64, 0x06ca6351e003826f_cppui64, 0x142929670a0e6e70_cppui64,
            0x27b70a8546d22ffc_cppui64, 0x2e1b21385c26c926_cppui64, 0x4d2c6dfc5ac42aed_cppui64, 0x53380d139d95b3df_cppui64,
            0x650a73548baf63de_cppui64, 0x766a0abb3c77b2a8_cppui64, 0x81c2c92e47edaee6_cppui64, 0x92722c851482353b_cppui64,
            0xa2bfe8a14cf10364_cppui64, 0xa81a664bbc423001_cppui64, 0xc24b8b70d0f89791_cppui64, 0xc76c51a30654be30_cppui64,
            0xd192e819d6ef5218_cppui64, 0xd69906245565a910_cppui64, 0xf40e35855771202a_cppui64, 0x106aa07032bbd1b8_cppui64,
            0x19a4c116b8d2d0c8_cppui64, 0x1e376c085141ab53_cppui64, 0x2748774cdf8eeb99_cppui64, 0x34b0bcb5e19b48a8_cppui64,
            0x391c0cb3c5c95a63_cppui64, 0x4ed8aa4ae3418acb_cppui64, 0x5b9cca4f7763e373_cppui64, 0x682e6ff3d6b2b8a3_cppui64,
            0x748f82ee5defb2fc_cppui64, 0x78a5636f43172f60_cppui64, 0x84c87814a1f0ab72_cppui64, 0x8cc702081a6439ec_cppui64,
            0x90befffa23631e28_cppui64, 0xa4506cebde82bde9_cppui64, 0xbef9a3f7b2c67915_cppui64, 0xc67178f2e372532b_cppui64,
            0xca273eceea26619c_cppui64, 0xd186b8c721c0c207_cppui64, 0xeada7dd6cde0eb1e_cppui64, 0xf57d4f7fee6ed178_cppui64,
            0x06f067aa72176fba_cppui64, 0x0a637dc5a2c898a6_cppui64, 0x113f9804bef90dae_cppui64, 0x1b710b35131c471b_cppui64,
            0x28db77f523047d84_cppui64, 0x32caab7b40c72493_cppui64, 0x3c9ebe0a15c9bebc_cppui64, 0x431d67c49c100d4c_cppui64,
            0x4cc5d4becb3e42b6_cppui64, 0x597f299cfc657e2a_cppui64, 0x5fcb6fab3ad6faec_cppui64, 0x6c44198c4a475817_cppui64};

    std::array<typename ed25519_type::base_field_type::integral_type, 80> message_schedule_array;
    std::array<typename ed25519_type::base_field_type::integral_type, 8> public_input = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                                                                                         0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};
    typename ed25519_type::base_field_type::integral_type one = 1;
    typename ed25519_type::base_field_type::integral_type mask = (one << 64) - 1;
    typename ed25519_type::base_field_type::integral_type Rx = typename ed25519_type::base_field_type::integral_type(R.X.data);
    typename ed25519_type::base_field_type::integral_type Ry = typename ed25519_type::base_field_type::integral_type(R.Y.data);
    typename ed25519_type::base_field_type::integral_type pkx = typename ed25519_type::base_field_type::integral_type(pk.X.data);
    typename ed25519_type::base_field_type::integral_type pky = typename ed25519_type::base_field_type::integral_type(pk.Y.data);
    message_schedule_array[0] = Rx & mask;
    message_schedule_array[1] = (Rx >> 64) & mask;
    message_schedule_array[2] = (Rx >> 128) & mask;
    message_schedule_array[3] = ((Rx >> 192) & mask) + (Ry & 1) * (one << 63);
    message_schedule_array[4] = (Ry >> 1) & mask;
    message_schedule_array[5] = (Ry >> 65) & mask;
    message_schedule_array[6] = (Ry >> 129) & mask;
    message_schedule_array[7] = ((Ry >> 193) & mask) + (pkx & 3) * (one << 62);
    message_schedule_array[8] = (pkx >> 2) & mask;
    message_schedule_array[9] = (pkx >> 66) & mask;
    message_schedule_array[10] = (pkx >> 130) & mask;
    message_schedule_array[11] = ((pkx >> 194) & mask) + (pky & 7) * (one << 61);
    message_schedule_array[12] = (pky >> 3) & mask;
    message_schedule_array[13] = (pky >> 67) & mask;
    message_schedule_array[14] = (pky >> 131) & mask;
    message_schedule_array[15] = ((pky >> 195) & mask) + (M[0] & 15) * (one << 60);
    for(std::size_t i = 16; i < 80; i ++){
        typename ed25519_type::base_field_type::integral_type s0 = ((message_schedule_array[i - 15] >> 1)|((message_schedule_array[i - 15] << (64 - 1))
                                                                                                           & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data))) ^
                                                                   ((message_schedule_array[i - 15] >> 8)|((message_schedule_array[i - 15] << (64 - 8))
                                                                                                           & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)))
                                                                   ^ (message_schedule_array[i - 15] >> 7);
        typename ed25519_type::base_field_type::integral_type s1 = ((message_schedule_array[i - 2] >> 19)|((message_schedule_array[i - 2] << (64 - 19))
                                                                                                           & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data))) ^
                                                                   ((message_schedule_array[i - 2] >> 61)|((message_schedule_array[i - 2] << (64 - 61))
                                                                                                           & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)))
                                                                   ^ (message_schedule_array[i - 2] >> 6);
        message_schedule_array[i] = (message_schedule_array[i - 16] + s0 + s1 + message_schedule_array[i - 7])%
                                    typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data);
    }
    typename ed25519_type::base_field_type::integral_type a = typename ed25519_type::base_field_type::integral_type(public_input[0]);
    typename ed25519_type::base_field_type::integral_type b = typename ed25519_type::base_field_type::integral_type(public_input[1]);
    typename ed25519_type::base_field_type::integral_type c = typename ed25519_type::base_field_type::integral_type(public_input[2]);
    typename ed25519_type::base_field_type::integral_type d = typename ed25519_type::base_field_type::integral_type(public_input[3]);
    typename ed25519_type::base_field_type::integral_type e = typename ed25519_type::base_field_type::integral_type(public_input[4]);
    typename ed25519_type::base_field_type::integral_type f = typename ed25519_type::base_field_type::integral_type(public_input[5]);
    typename ed25519_type::base_field_type::integral_type g = typename ed25519_type::base_field_type::integral_type(public_input[6]);
    typename ed25519_type::base_field_type::integral_type h = typename ed25519_type::base_field_type::integral_type(public_input[7]);
    for(std::size_t i = 0; i < 80; i ++){
        typename ed25519_type::base_field_type::integral_type S0 = ((a >> 28)|((a << (64 - 28))
                                                                               & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data))) ^
                                                                   ((a >> 34)|((a << (64 - 34))
                                                                               & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)))
                                                                   ^ ((a >> 39)|((a << (64 - 39))
                                                                                 & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)));

        typename ed25519_type::base_field_type::integral_type S1 = ((e >> 14)|((e << (64 - 14))
                                                                               & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data))) ^
                                                                   ((e >> 18)|((e << (64 - 18))
                                                                               & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)))
                                                                   ^ ((e >> 41)|((e << (64 - 41))
                                                                                 & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)));

        typename ed25519_type::base_field_type::integral_type maj = (a & b) ^ (a & c) ^ (b & c);
        typename ed25519_type::base_field_type::integral_type ch = (e & f) ^ ((~e)& g);
        typename ed25519_type::base_field_type::integral_type tmp1 = h + S1 + ch + round_constant[i] + message_schedule_array[i];
        typename ed25519_type::base_field_type::integral_type tmp2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = (d + tmp1)%
            typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data);
        d = c;
        c = b;
        b = a;
        a = (tmp1 + tmp2)%
            typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data);
    }
    std::array<typename ed25519_type::base_field_type::integral_type, 8> output_state = {(a + typename ed25519_type::base_field_type::integral_type(public_input[0]))%
                                                                                         typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
                                                                                         (b + typename ed25519_type::base_field_type::integral_type(public_input[1]))%
                                                                                         typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
                                                                                         (c + typename ed25519_type::base_field_type::integral_type(public_input[2]))%
                                                                                         typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
                                                                                         (d + typename ed25519_type::base_field_type::integral_type(public_input[3]))%
                                                                                         typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
                                                                                         (e + typename ed25519_type::base_field_type::integral_type(public_input[4]))%
                                                                                         typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
                                                                                         (f + typename ed25519_type::base_field_type::integral_type(public_input[5]))%
                                                                                         typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
                                                                                         (g + typename ed25519_type::base_field_type::integral_type(public_input[6]))%
                                                                                         typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
                                                                                         (h + typename ed25519_type::base_field_type::integral_type(public_input[7]))%
                                                                                         typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data)};
    typename ed25519_type::base_field_type::integral_type bits_amount = 255*4+256;
    message_schedule_array[0] = ((M[0] >> 4) & mask) + (M[1] & 3) * (one << 62);
    message_schedule_array[1] = (M[1] >> 2) & mask;
    message_schedule_array[2] =  M[2] & mask;
    message_schedule_array[3] = (M[2] >> 64) + (M[3]) * (one << 2) + 1 * (one << 60);
    message_schedule_array[4] = 0;
    message_schedule_array[5] = 0;
    message_schedule_array[6] = 0;
    message_schedule_array[7] = 0;
    message_schedule_array[8] = 0;
    message_schedule_array[9] = 0;
    message_schedule_array[10] = 0;
    message_schedule_array[11] = 0;
    message_schedule_array[12] = 0;
    message_schedule_array[13] = 0;
    message_schedule_array[14] = 0;
    message_schedule_array[15] = bits_amount;
    for(std::size_t i = 16; i < 80; i ++){
        typename ed25519_type::base_field_type::integral_type s0 = ((message_schedule_array[i - 15] >> 1)|((message_schedule_array[i - 15] << (64 - 1))
                                                                                                           & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data))) ^
                                                                   ((message_schedule_array[i - 15] >> 8)|((message_schedule_array[i - 15] << (64 - 8))
                                                                                                           & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)))
                                                                   ^ (message_schedule_array[i - 15] >> 7);
        typename ed25519_type::base_field_type::integral_type s1 = ((message_schedule_array[i - 2] >> 19)|((message_schedule_array[i - 2] << (64 - 19))
                                                                                                           & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data))) ^
                                                                   ((message_schedule_array[i - 2] >> 61)|((message_schedule_array[i - 2] << (64 - 61))
                                                                                                           & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)))
                                                                   ^ (message_schedule_array[i - 2] >> 6);
        message_schedule_array[i] = (message_schedule_array[i - 16] + s0 + s1 + message_schedule_array[i - 7])%
                                    typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data);
    }
    a = typename ed25519_type::base_field_type::integral_type(output_state[0]);
    b = typename ed25519_type::base_field_type::integral_type(output_state[1]);
    c = typename ed25519_type::base_field_type::integral_type(output_state[2]);
    d = typename ed25519_type::base_field_type::integral_type(output_state[3]);
    e = typename ed25519_type::base_field_type::integral_type(output_state[4]);
    f = typename ed25519_type::base_field_type::integral_type(output_state[5]);
    g = typename ed25519_type::base_field_type::integral_type(output_state[6]);
    h = typename ed25519_type::base_field_type::integral_type(output_state[7]);
    for(std::size_t i = 0; i < 80; i ++){
        typename ed25519_type::base_field_type::integral_type S0 = ((a >> 28)|((a << (64 - 28))
                                                                               & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data))) ^
                                                                   ((a >> 34)|((a << (64 - 34))
                                                                               & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)))
                                                                   ^ ((a >> 39)|((a << (64 - 39))
                                                                                 & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)));

        typename ed25519_type::base_field_type::integral_type S1 = ((e >> 14)|((e << (64 - 14))
                                                                               & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data))) ^
                                                                   ((e >> 18)|((e << (64 - 18))
                                                                               & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)))
                                                                   ^ ((e >> 41)|((e << (64 - 41))
                                                                                 & typename ed25519_type::base_field_type::integral_type((typename ed25519_type::base_field_type::value_type(2).pow(64) - 1).data)));

        typename ed25519_type::base_field_type::integral_type maj = (a & b) ^ (a & c) ^ (b & c);
        typename ed25519_type::base_field_type::integral_type ch = (e & f) ^ ((~e)& g);
        typename ed25519_type::base_field_type::integral_type tmp1 = h + S1 + ch + round_constant[i] + message_schedule_array[i];
        typename ed25519_type::base_field_type::integral_type tmp2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = (d + tmp1)%
            typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data);
        d = c;
        c = b;
        b = a;
        a = (tmp1 + tmp2)%
            typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data);
    }
    std::array<typename ed25519_type::base_field_type::extended_integral_type, 8> result_state1 = {(a + typename ed25519_type::base_field_type::integral_type(output_state[0]))%
                                                                                                   typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
                                                                                                   (b + typename ed25519_type::base_field_type::integral_type(output_state[1]))%
                                                                                                   typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
                                                                                                   (c + typename ed25519_type::base_field_type::integral_type(output_state[2]))%
                                                                                                   typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
                                                                                                   (d + typename ed25519_type::base_field_type::integral_type(output_state[3]))%
                                                                                                   typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
                                                                                                   (e + typename ed25519_type::base_field_type::integral_type(output_state[4]))%
                                                                                                   typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
                                                                                                   (f + typename ed25519_type::base_field_type::integral_type(output_state[5]))%
                                                                                                   typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
                                                                                                   (g + typename ed25519_type::base_field_type::integral_type(output_state[6]))%
                                                                                                   typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data),
                                                                                                   (h + typename ed25519_type::base_field_type::integral_type(output_state[7]))%
                                                                                                   typename ed25519_type::base_field_type::integral_type(typename ed25519_type::base_field_type::value_type(2).pow(64).data)};
    typename ed25519_type::scalar_field_type::value_type two = 2;
    typename ed25519_type::scalar_field_type::value_type res = result_state1[0] + result_state1[1] * two.pow(64) + result_state1[2] * two.pow(128)
                                                               + result_state1[3] * two.pow(192) + result_state1[4] * two.pow(256) + result_state1[5] * two.pow(320) + result_state1[6] * two.pow(384) +
                                                               result_state1[7] * two.pow(448);

    return res;
}

int main(int argc, char *argv[]) {
    using curve_type = algebra::curves::ed25519;
    using integral_type = curve_type::base_field_type::integral_type;
    using value_type = curve_type::scalar_field_type::value_type;

    typedef hashes::sha2<256> hash_type;
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

#ifndef __EMSCRIPTEN__
    boost::program_options::options_description options("Solana 'Light-Client' State Mock Data Generator");
    // clang-format off
    options.add_options()("help,h", "Display help message")
            ("packets,p", boost::program_options::value<std::size_t>()->default_value(0), "Amount of packets to mock")
            ("input,i", boost::program_options::value<std::string>(), "Data from cluster")
            ("validators,v", boost::program_options::value<std::size_t>()->default_value(distrib(gen)),
             "Amount of validators to emulate");
    // clang-format on

    boost::program_options::positional_options_description p;
    p.add("input", 1);

    boost::program_options::variables_map vm;
    boost::program_options::store(
            boost::program_options::command_line_parser(argc, argv).options(options).positional(p).run(), vm);
    boost::program_options::notify(vm);

    if (vm.count("help")) {
        std::cout << options << std::endl;
        return 0;
    }

    std::string string;
    bool input_state = false;
    if (vm.count("input")) {
        input_state = true;
        if (boost::filesystem::exists(vm["input"].as<std::string>())) {
            boost::filesystem::load_string_file(vm["input"].as<std::string>(), string);
        }
    }

    const std::size_t k = vm["validators"].as<std::size_t>();
#endif

    random_hash_generator_type hash_gen;
    status_type s;
    constexpr const std::size_t batch_size = 13;
    state_type<hash_type, curve_type> state;

    if (!input_state) {
        state.confirmed = static_cast<size_t>(distrib(gen));
        state.new_confirmed = distrib(gen) + state.confirmed;

        std::size_t blocks_count = distrib(gen);
        std::vector<uint64_t> timestamps;
        std::generate_n(std::back_inserter(timestamps), blocks_count, [] {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count();
        });

        for (int i = 0; i < blocks_count; i++) {
            state.repl_data.push_back({
                                      .block_number = static_cast<size_t>(distrib(gen)),
                                      .bank_hash = pack<nil::marshalling::option::little_endian>(hash_gen(), s),
                                      .previous_bank_hash = pack<nil::marshalling::option::little_endian>(
                                              hash_gen(), s),
                                      .timestamp = static_cast<uint32_t>(timestamps[i]),
                                      });
        }
    } else {
        boost::json::monotonic_resource mr;
        state = boost::json::value_to<state_type<hash_type, curve_type>>(
                boost::json::parse(string, &mr));
    }

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type B =
            curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type::one();
    multiprecision::number<multiprecision::cpp_int_backend<256, 256>> M = pack(
            state.repl_data[state.repl_data.size() - 1].bank_hash.begin(),
            state.repl_data[state.repl_data.size() - 1].bank_hash.end(), s);
    integral_type base = 1;
    integral_type mask = (base << 66) - 1;
    std::vector<curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type> signatures_point;
    std::vector<curve_type::scalar_field_type::value_type> signatures_scalar;
    std::vector<curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type> public_keys_values;
    for (std::size_t i = 0; i < k; i++) {
        value_type r = algebra::random_element<curve_type::scalar_field_type>();
        value_type c = algebra::random_element<curve_type::scalar_field_type>();

        curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type R = r * B;
        signatures_point.emplace_back(R);
        curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type P = c * B;
        public_keys_values.emplace_back(P);
        auto sha_output = sha512<curve_type>(R, P, {curve_type::base_field_type::integral_type(M & mask),
                                                    curve_type::base_field_type::integral_type((M >> 66) & mask),
                                                    curve_type::base_field_type::integral_type((M >> 132) & mask),
                                                    curve_type::base_field_type::integral_type((M >> 198) & mask)});
        signatures_scalar.emplace_back(r + sha_output * c);
    }

    std::size_t all_batches = k;
    std::size_t cur_batch = 0;
    state.votes.resize((k - 1) / batch_size + 1);

    state.bank_hash = state.repl_data[state.repl_data.size() - 1].bank_hash;
    while (all_batches > 0) {
        state.votes[cur_batch].resize(std::min(batch_size, all_batches));
        for (std::size_t i = 0; i < batch_size && all_batches > 0; ++i, --all_batches) {
            state.votes[cur_batch][i].pubkey = {integral_type(public_keys_values[k - all_batches].X.data), integral_type(
                    public_keys_values[i].Y.data)};
            state.votes[cur_batch][i].signature = {.points = {integral_type(signatures_point[k - all_batches].X.data), integral_type(
                    signatures_point[i].Y.data)}, .scalar = signatures_scalar[k - all_batches]};
            state.votes[cur_batch][i].weight = static_cast<size_t>(small_distrib(gen));
        }
        ++cur_batch;
    }

    boost::json::value jv = boost::json::value_from(state);
    pretty_print(std::cout, jv);

    return 0;
}