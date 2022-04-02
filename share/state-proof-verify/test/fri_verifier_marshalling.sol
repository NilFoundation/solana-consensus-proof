// SPDX-License-Identifier: MIT OR Apache-2.0
//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

pragma solidity >=0.8.4;
pragma experimental ABIEncoderV2;

import "truffle/Assert.sol";
import '../contracts/cryptography/types.sol';
import '../contracts/commitments/fri_verifier.sol';
import '../contracts/cryptography/transcript.sol';

// TODO: add false-positive tests
contract TestFRIVerifierMarshalling {
    function test_fri_proof_marshalling() public {
        // tree depth = 5
        bytes memory raw_proof = hex"2bf4c75f7fe2126f88761b90ff29f3ee787d0a294fb1a7f2e7a2fffbe8a2963f000000000000002083650fe4b3d91b1e78f0b3bcfc437b55f1b70f66d4507092685e9cde9d1ae7d9000000000000000240db90e0ac8421dd6ff25e3803c3af26464ab1a916f6be66e8745ae1ab59e6c5278374d4639ae70cd58237506fe0e86231a6eccefa7c14cbeae1014d368778ac000000000000001a00000000000000208725b07396b5ae1a11b7986fe80880f4fb4d5c266445f773f0fa85f4b32ce026000000000000000500000000000000010000000000000001000000000000002018f4f4b95d5fde947f92d0b1e410bbb3900e7140da6b4edd78acf78a6dcb8c6d000000000000000100000000000000000000000000000020f3b3ad363d5334dda6f2a2c056f599780916ceabe4b882527e5d5e6eb9a1bdd70000000000000001000000000000000100000000000000201f2acda2d0ba7a523ef704ade88a2becb6f24f44b07a4eb8456d14cc2bb582a5000000000000000100000000000000000000000000000020749e7650f8168f2d4cedbd40678b97f777736dfa12508600eeccbd38826240bd0000000000000001000000000000000000000000000000203b4b235c744e3eb3354b07bc167d8eab443ab366f14f3eb41ce076a6bfd2629f000000000000000200000000000000160000000000000020f272558e1aa215d4c993c98f05d2a08f810b01aef7b446e9ec813ad2832ecb8c0000000000000005000000000000000100000000000000010000000000000020388f722755a1e669b0342693057a975d8e3d6228bc01f29765586dce08a07fb4000000000000000100000000000000000000000000000020a5a51345efaf6b7829c72f78e4b11c7fd990c114ec558e8fcb09ae7cdcb9e140000000000000000100000000000000000000000000000020afcb22c80bf300448287325042989c0c3336da28096b774f508afef6aaec5fd50000000000000001000000000000000100000000000000209fe0d0d063a58453bc1df76608249e0e0858e5c9e954aa3047df21585a615a7a00000000000000010000000000000000000000000000002088adcde89d06f6fa1eef78d563365a390840368b23983e25ae66ad891885b3c400000000000000130000000000000020e87e8268b1e23884c170c90e07258abf4a0b308f62b47a0399e35d53df9b9faf0000000000000005000000000000000100000000000000000000000000000020ed70a558d720f7e82f2107bb975a483d05d702b3b023933bcd9fab25c1a70cfd000000000000000100000000000000000000000000000020a36d9a2a21233d72b8534efc2e4bf75f12e8c41fe5b3904071d3bfdf09d355ee000000000000000100000000000000010000000000000020ab83d0fa0d580c45d799d7d1385e1a6f15e108727f8d209aa83709debb4aaf7f0000000000000001000000000000000100000000000000202db5dbde2659e81a6eef59eaac97325ed7bd01f8166594cf575e3bea4bc658ed00000000000000010000000000000000000000000000002052e476f4f80f907e3551f0d3e986da01460f6504df84c30b39d6a3db9041dd0e";
        (types.fri_round_proof_type memory round_proof, uint256 round_proof_size) = fri_verifier.parse_round_proof_be(raw_proof, 0);
        Assert.equal(raw_proof.length, round_proof_size, "Round proof length is not correct");
        uint256[2] memory etalon_y = [uint256(29335961725185576543323499320733178417526223883075320915687427256572505089733), uint256(17872464388807918718962722713254896551988475509500926988741272471702025500844)];
        uint256 etalon_colinear_value = 19881939195071986852360266395256556670266930866322317437977032550321794225727;
        bytes32 etalon_T_root = hex"83650fe4b3d91b1e78f0b3bcfc437b55f1b70f66d4507092685e9cde9d1ae7d9";
        Assert.equal(round_proof.y.length, etalon_y.length, "Round proof y length is not correct");
        for (uint256 i = 0; i < etalon_y.length; i++) {
            Assert.equal(round_proof.y[i], etalon_y[i], "Round proof y is not correct");
        }
        Assert.equal(round_proof.colinear_value, etalon_colinear_value, "Round proof colinear_value is not correct");
        Assert.equal(round_proof.T_root, etalon_T_root, "Round proof T_root is not correct");
        bytes32 colinear_path_verifiable_data = hex"3724165e3e9023cc0c4235dcbc23b26ad6efe791382b3f8ef17393ae4a9c576f";
        Assert.equal(true, merkle_verifier.verify_merkle_proof(round_proof.colinear_path, colinear_path_verifiable_data), "Round proof colinear_path is not correct");
        bytes32[2] memory p_verifiable_data = [bytes32(hex"9ab21704eef4cd6a6b2f099c5b4a61657ee97aba9acac785c8d63b98f5ee8054"), bytes32(hex"5a3f50b2f00a3934014fa5ae9999b8ddda35d246d4f8770bac66e4d92b3e6b6a")];
        Assert.equal(round_proof.p.length, p_verifiable_data.length, "Round proof y length is not correct");
        for (uint256 i = 0; i < etalon_y.length; i++) {
            Assert.equal(true, merkle_verifier.verify_merkle_proof(round_proof.p[i], p_verifiable_data[i]), "Round proof p is not correct");
        }

        // tree depth = 5, round proofs number = 6, final polynomial degree = 7
        raw_proof = hex"000000000000000729706b2dcda62c56d9431126286d483aa4b7e21365d076659680a7c35f6ab642709332f403b31d8d535d56217d76ec8ffa3d3e964b1c0ac5c5429028881cd5541c60080a296fc3dda1d86b49f1dcf1bbab16706b2f4c434cc69675ac20014e5c389d54aac22168c46600fcd16c334539ca62f88d1f02ac8362644f2f9dec75660b8caeb01906a7bcd298c46e9e36a3fd89a556a5d1edc1a2ab83b624ebbcb6de65f938fc37f01015b7b280f273b8d060132d27a8922b5761f1e2b13c22f31d0e694d348601eb3544866e5e029f1ddcde5c05457a8c9933b119bbff7386e7511d00000000000000065b6ff8674242fe16b407930247e002ea6a5f86a10a1485b218a36e3ed6bfcd7200000000000000200760d1d656015502e148aceb9863cbd711bb029cdf23b382b47f8b71868c39190000000000000002387ecc293282fb3e11784c6ded1096828bf2b4a0ceefe6ec0b789552b6e473766c6ad115ebb47c0099f4640ed1ba9155ca011005d687fe8232489f5b65af1ea200000000000000070000000000000020ba020cc7f62aa9382d5772cf6b14b7ea11eb3795786fda43b647f1e6acc0e02200000000000000050000000000000001000000000000000000000000000000203cea43e4547f8df0f139ff6b776eccdab89bfe5e879cbb8b096030cbda7cb9ab0000000000000001000000000000000000000000000000203a20bb21753297feda1bbf57b9aacbd0b6641ddcc135c45acfed552cf22a015700000000000000010000000000000000000000000000002058f0ec89663207e529c2a5a24101ba62608d47592922500fec365a4bab99fde00000000000000001000000000000000100000000000000204ee3eb745bb0543b533473f14e52607056efe9a6960e81df576621ea5d302ffa000000000000000100000000000000010000000000000020c620a3352325380b491204ac69add5234c1628b48a36c6b9e0e7eda2e5e03707000000000000000200000000000000130000000000000020ab1fe26fe1235af87760a9d0d22b53d1790c3349d6f08e493dc388d61ef5770d0000000000000005000000000000000100000000000000000000000000000020b90ab51c0ab6667950b995def5060ff8b7f92622cba0a8ac9b5eadfafafdaf60000000000000000100000000000000000000000000000020f17208915586810b53b2827808ddaa2c42454a936c8d9bdff01365813d8f2cb50000000000000001000000000000000100000000000000203345b65ee658a36f0c58df579ae99410985d392365cb1818df2fbd249e8dd296000000000000000100000000000000010000000000000020a09fa27167705300886718d40a10681c260876ce9955e7a33b7d46c0cfaa561d00000000000000010000000000000000000000000000002013329e0b04dbd67e853769a3cb020ec2efb6101f3c09c0f0a9e18da07fc682580000000000000001000000000000002071648b883ac5e754b58f0b12877afd8cf08b244ac688c31f75e0bc70ace8e54f000000000000000500000000000000010000000000000000000000000000002005ee999cac63e7d2ba2d57d1a53095e59977dd9b814c121ee4b12e38d560db3100000000000000010000000000000001000000000000002004b02ce4b78741ac0ed1227dafa399009e7e12da85507c1cd8d7d215faa58197000000000000000100000000000000010000000000000020c8a8398d6966b73eda9b6a231e55a403b48c3b3aed008db858d0cb9be4ad630b0000000000000001000000000000000100000000000000208256af5fc44f583e8bcb6d990b33b631c5cf4ba22e761c74691228a97a625cf00000000000000001000000000000000100000000000000207daaaf680dc74f8e459c83babbdf761138395e22d90d5f496ec02bc8295030861b0c1ef79aeab5d81f75eb41a265f0f299c537896c6b756643c268084dc818a80000000000000020117b36bd126738d9027f60b359072d7fb34b91d128976e377892ebad4dd563b7000000000000000213ac6c90bf27c72897506bf727e8423ddf10c7b70483a501f2bbae518972dad349af187f9c41a39d4660aa30ec296af5b74d93bdb6efccd0f6159ef0da7d381d00000000000000160000000000000020122100661721ae45cadff887add4f7a16dd8f03eab970f32135325b13e534fd0000000000000000500000000000000010000000000000001000000000000002025fe44237bbca1517f89d0eae43d45abe472ecec9da63a6e6c376b58f6d57858000000000000000100000000000000000000000000000020a42de92d19374b3664e84071ef780d11c51b2e3a093734f3806d62ac22e6b73a0000000000000001000000000000000000000000000000206e7bf1ad112ef98a868a9521aa91ee0054d39c4a699fb7390119067dce8b015a00000000000000010000000000000001000000000000002087ca81bbce21529f9c7f030d54339f97d9efc0e9d9ed3b8bd7d04ee7a08f1f2000000000000000010000000000000000000000000000002036b53cdf1f8ca1bf0172ea30a99328aad976e9dcc4663fcd3b184c5c6172c8e90000000000000002000000000000000e000000000000002099be9a579b7a90998852bdf2fc8f3540064a050a2a09ca7c00b91e7fc80dd94f000000000000000500000000000000010000000000000001000000000000002011d77d9c147f1e4ed3a0b30a6f268bff5e6006976bd763017a8fd7944947090e000000000000000100000000000000000000000000000020ae356181623f787dacd54ebbe66a78b7b44011a1c9b05d3c98e6feb48d2aa8db0000000000000001000000000000000000000000000000203884510002fcf8c5fd2fbe254a15abf6630a992b2de905ed1df143f1780ce3e2000000000000000100000000000000000000000000000020760c7e518a829096db710519bb74993ca0c5c03f980b022e4602a2fa088791420000000000000001000000000000000100000000000000202ba73e02cf5c55206d4c8ced0342b63a9000a4d530dd3fd73534763e3b29a47e000000000000001f0000000000000020dd595492b37ce1b64e78c452ffdd9b9f75504337b7f10a268239e0a2868cf3330000000000000005000000000000000100000000000000000000000000000020a4b1be67c52ea32710597e118e2b43fa7ac9ab5f816323bffab3fbe7336566fa0000000000000001000000000000000000000000000000207ae4efd7a2fc8bb642b509068554dcbd2b114b37c471b31533281bdb8625a6ec0000000000000001000000000000000000000000000000206a1d5f89d9511b48fdf9561d3f5c70301a9d7a40ea38f33f1ffe55704932eb060000000000000001000000000000000000000000000000201e9321bd16b5362afd39b53327e5c1d07fae576d2648e0e64fbf4a3c0472690b00000000000000010000000000000000000000000000002025b4a6dbae01fe83eb4d86ff735a51dcad4998455c364d50df69e074fdd66ccf6e59a094d1c35f750c9abbd36426f0b5c102d2ecbbeb5a052a738bf78c40a20d00000000000000207c17a2a30f4d2c858ae121bdb04c40119b6efec6eaa58efb15ccd744695145c300000000000000025ac25c9e110cebc5cc68989f8b895354be0a57472c208e4582a827bedf25082246d152ec48659d1bc4d21f6cd916476ffa916c9deb36eff38dcf86314665105b0000000000000010000000000000002049da62c98b6f0defdfb30085a452e6323e3769595abfbc4566c7a9d35c81d180000000000000000500000000000000010000000000000001000000000000002038f516b77014516597c5b3f392e84baccbff26cfea242c9910c24ab9d9716736000000000000000100000000000000010000000000000020f876caf57addd0508bac570067f67f61f6b24c31e9444186b53474724de97289000000000000000100000000000000010000000000000020f6ed48e51d5d25bc7c1226876fc98736a4d65d7981aeefdb5057e1693508703c0000000000000001000000000000000100000000000000209c536a7b632bec56c8fc86a2d03de87105b1d9e7c63f842bf3f0308e6bcf7d6a000000000000000100000000000000000000000000000020185e6d94e5ce890ce39ecb675de2ccb7cf23d0d5331662e2af3561fa9a9fa6980000000000000002000000000000000d0000000000000020321260531daa6d0c76afc2b5efda90cadd08e482681f5afb4a03f264098a519a0000000000000005000000000000000100000000000000000000000000000020879d7d73ebd1c3fb3f2e0899022c32b000cdfb83989a4eaba0345b693a076076000000000000000100000000000000010000000000000020c26ac626ea0f0bc11ebce80d3eb1465be246e7d47e182b4307e27d622b4175db000000000000000100000000000000000000000000000020831e932358630997f0f76cc8b0b3c6ca3c7ac8e96934392cdd45d76d7270c3ba000000000000000100000000000000000000000000000020b2b04f12942097a6d95f76829939996f9cac6303f9d298942791dedd3f3c4045000000000000000100000000000000010000000000000020530313af24220b4dae33156d833eab0de635ce0becc44edbfa543c28ff08b238000000000000000600000000000000209164c973c61bdfc427af77ff13081483d0b57cc23ff673787426216306bd3ab300000000000000050000000000000001000000000000000100000000000000206277ec98427dc33455302f2298f505448581455c228d779771871ddf3b777aa5000000000000000100000000000000000000000000000020740281ae3c39a515819a85a99240ef4e43b5072c2940e132a14881ddda4aa5aa0000000000000001000000000000000000000000000000206c51af932eb5662f874bb262e1855b027b490ee530af80af7a66b72ad792a240000000000000000100000000000000010000000000000020f02b2a82ef9cf16ee382d77e2a7f9b2a72cb6710d2abfa3d700754900e2e4953000000000000000100000000000000010000000000000020c4b11725fa6be240bd17bf28b931b9c4b30d5cc86a55f6687d8c9eedadfab61e48837fc0ceeed57b8a1a96d70c1c923aba0495196bfc0a4ee319db730c448ff500000000000000203cb1b78fac09a3ed515e30ec80e019630c18967b2925380328e0c7763dc6f2e9000000000000000227fb82099321b1508811e98ce7da025f0e25e0ca11debaf1b487307362263d143cb6a6ed7e51fa27b682e183eab8787d7419e38a85b73beaaec089a8dd2112fb000000000000001900000000000000204179670c669439807e9da60b68efb99a64f7ab0cbc336eada462f1a6bfcdd7710000000000000005000000000000000100000000000000000000000000000020122f819809ea02cdbec39729dc1b3c9e27891d07f8b9ab2ab8d0220f59a1dbc90000000000000001000000000000000100000000000000209a117f592bddd503f9e5fddc929ce4259d0f4ebe27ef77e62396c5f8212231eb000000000000000100000000000000010000000000000020209e129e5ae762aeaf0d7bb025a9d5958a12d76605794ca231939ce722bb26bb00000000000000010000000000000000000000000000002048f649205122a2deec85d1f61a6a10c7b3ec910268371c74186b4f2453fc516a0000000000000001000000000000000000000000000000208dbf36ae65b9ed46b234a88ff7d10cb5c158653d0b014b2055bddcfdeda98c970000000000000002000000000000000e000000000000002062788fad3cbd6e0406c8b92e7be1641af98cb5b62f27a4949d387217d7cb48d1000000000000000500000000000000010000000000000001000000000000002098b32bc5bca3537ac2b830007d27ed882714b662dccb5b23afe71ea2a88cfaea0000000000000001000000000000000000000000000000206db55f1540999587690a7163f2a80602848836468f69b30d8d6318f0db4d99eb0000000000000001000000000000000000000000000000206d922fc7f111f9bc6ac2e1c84cddab74e2202ed21034d5d3d76758903fc5091f00000000000000010000000000000000000000000000002061e66abb370f87d1f0dcf299d119b35d67e31db7e1fb2b2dfb36bd8265834806000000000000000100000000000000010000000000000020b963835ad12dbf22fa7ee81a564e05d03641e35ad29acd1d74f5785bbf6f7fc1000000000000000b0000000000000020565274409c1305209e821f5c61399468198e1d7784b5d8d7c96ee059db5df92f0000000000000005000000000000000100000000000000000000000000000020ce87af8f793178fc5ee2e7baac9d5c1d69f1e5956ab386e9f4c9e054bab8b0030000000000000001000000000000000000000000000000204bb174702ee67bddcee85274b077e48d472ff9c674acb7216a5f6371e9b456fb00000000000000010000000000000001000000000000002064c41a5a316755a43ce3a652cc7e2c6de283cd758d3ec6dd49e6722ba99e39e3000000000000000100000000000000000000000000000020837276b895e7ec3d6b412af5130fb946a0d720c3af05474af76b7569d70bfafb0000000000000001000000000000000100000000000000201220bd3ee159042fc3a19f1bd83e856b0de505b98efbe58ab7b27bc0874b1c347293f1254bb3d75ae868efdd1eb6113de866bc6d029f0d208541bb06e48e3e3b0000000000000020c36edb43451e9e7cd05028b0494c2403ccb36b86e74e7f58370f794e43079dc600000000000000020a8d7d3150b0ebf8eb18eaf9ed7d4f2cb5667d50ca684bdb27259b8c702895be457aa7ca9ae31d54a9d6415754243f3472c6b534699622b699858200c4a71e83000000000000001500000000000000209cdad52818e06f3b19c92e468dd6f3daf45e0027282880db09a7bb7479313e050000000000000005000000000000000100000000000000000000000000000020df8294f75de9c46c938f57478a3148a1bc0558264038573e2e60689915d9c80f000000000000000100000000000000010000000000000020f0e41aa990b99adf756cad4b50efd9304ac27a8e49e38a2fdf3027a87fa04c5d000000000000000100000000000000000000000000000020993105e03375418005f034f90a9d49e55c07cf149090232e4694dd045e0cf1a0000000000000000100000000000000010000000000000020cfddfb428956caee8489aa5ab1119d1c38b34ef01fd3b8f7cfd07f13496b5808000000000000000100000000000000000000000000000020ea7d3c9b6810e098625c5b046d2ee73e48d3193d0aea3d5ae99c5ab348b45698000000000000000200000000000000040000000000000020200fbe5a47d858883c10362e25d07e6817053d386b8f0d58f5a79810f5ec069400000000000000050000000000000001000000000000000100000000000000203dd698ea9d6a85b2d1527f9b062b0cac4ae9d25119673adf60bd644531ad68ec0000000000000001000000000000000100000000000000202ddf333998ec98985fb4f145324e2562fcd0017760bcb664232648e6ca873385000000000000000100000000000000000000000000000020cab20ff7347c8ad583ef040a5f4cba67a2334b2728c96cf71c1f58277b7c9c2000000000000000010000000000000001000000000000002088bc04785ab4f241cea24817a169aa66f8356c324c10e817b7e65c37559129a5000000000000000100000000000000010000000000000020a737186e2fcbc92e1e28feb86211fcf839913b3b676ba3cdb75e11e13a1e5057000000000000001f0000000000000020979faa467a85406c41a586795b75fa1c37f47dcb1546467172add499061cbbfd0000000000000005000000000000000100000000000000000000000000000020ce4e82edfb51846e090c757a6673892f1e760871624a3e5b7e0d8cf36cf39b310000000000000001000000000000000000000000000000202e9372e1991359d2e64ad47a6f1f01cbdba04310b80d5ebe69439994547197bf000000000000000100000000000000000000000000000020b9f24496fd5ed0f5af982fe7a9d7482047c58ff88b1d6c878395695ff446e31b00000000000000010000000000000000000000000000002062c8bdbd998a4c07802b74d31bccce82a3b1dae70d716365e58166aba7fbb67d00000000000000010000000000000000000000000000002041c2eb15f5766a3698da98462906eeb87c1cffe0bfbc6a23955610f38d2f4d37686b23bee7e91732c17e16870fef5f2d39f97446987cc3b251a5c4dd87cb90f900000000000000205999448f1ad99051252b407d127884d70d18e052cb850a9d422395525d65146900000000000000021dbeb4d746fd9822344bd29455a5cce42b48190d45beaa66901244929c7d63a35cd4a947427729aaa66fe721797771b4e8c9ac975ed6e98bd3cc78eb03598e85000000000000000e00000000000000204ff708282ed5f160a14736ad6d8283fd672401927c53ceb7204df1d4ce7aecb60000000000000005000000000000000100000000000000010000000000000020f529bad0d55bde6c606ee774e80349f37a307c954a532cc68109b0eee7a5b30a0000000000000001000000000000000000000000000000205ff97b0a33a440b99e642f5ab44a1bb18e57ffe2f6dc9385a66679c8f74ceecd000000000000000100000000000000000000000000000020d5d8cba988900d6dd342a5e49f566f28bc0386a1cf15a23f415e3ae701cfa45700000000000000010000000000000000000000000000002059774de7263d69d1fb217774cc313e8d2e059ecdb4659a88c7ba7e76a6b44db2000000000000000100000000000000010000000000000020c32e8b61db6f91e2168fd6349039d1d3bb2fa12da1321299e5099d63f1c654de0000000000000002000000000000001a00000000000000204683e5c930057eb299c03a2ae693368f2472e8ac9b4c4dd938cdeb19c9b1618100000000000000050000000000000001000000000000000100000000000000207743ceba36a3c3078392c738082712bc90523d5fd8cada3afca88a4586272d85000000000000000100000000000000000000000000000020a4d8f0b234879a3812796f1280a80a7ba67defde60f82a956da230d8fb372505000000000000000100000000000000010000000000000020080247077402c3f48843d284d697d309497436e5548428c0858981dfd2f447b4000000000000000100000000000000000000000000000020dab73101e05f3aae7c09ca8530d6a6ca4c355c7072e0af826e16743619fca199000000000000000100000000000000000000000000000020be31c9c6a352cd3dcb3ab24b54d2d3f9df54ee30b8830673dbb460b0b328d4fc000000000000000500000000000000206577aee3aa763f8d1a0739bf53f99dc7b7ed34e78e888ef0d515a51be389d1940000000000000005000000000000000100000000000000000000000000000020aca7acbe076006f82b35f9dd77b4aba338667c18ebeb1057dc6b31080692b868000000000000000100000000000000010000000000000020c74fd8ab5a7fa24dc6dc6ddd214e62ad826c9c511165763c3f1e9aae41981bbe000000000000000100000000000000000000000000000020531809a29a67e5ee0be282835932bd0bc6a70e62727180166ee78fd1c92208510000000000000001000000000000000100000000000000205848d9375b3fc18e6bcfadbbdea4739788f7ca26e7a90b3329127bf32cf4369c000000000000000100000000000000010000000000000020471533ed83b163efd9089b827b757c037b8fbe4c8a4fd4b0079f9b5c17a32a5a";
        (types.fri_proof_type memory proof, uint256 proof_size) = fri_verifier.parse_proof_be(raw_proof, 0);
        Assert.equal(raw_proof.length, proof_size, "Proof length is not correct");
        Assert.equal(raw_proof.length, fri_verifier.skip_proof_be(raw_proof, 0), "Skipping proof is not correct");
    }

    function test_fri_proof_verification_d16() public {
        // bn254 scalar field
        uint256 modulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        bytes memory raw_proof = hex"0000000000000001149350a3f93911fe5cc82ac9c65d277638725f97e2c4a8967d6b56bb8f40760c00000000000000040334a5283db3d274f3af1786d36ef745afe16e4a823705ad8db657bc1671c2f700000000000000200f044be55eca548bd7963cc4cfb11adb7a3b043c3f300c80eba0fdcc7900353600000000000000020559201106e80dedf628230cd76d081bf8b42137cf2c9d6bb862f2fbcafd37a31278f47c764d688ed5ea487d2cd262139c57874aa1b1c5406e59ac5ae0597dba00000000000000010000000000000020340e65a1d4528bd4a8ca97765eff0e5b95b51e0baf255176f6b7b707f95eae590000000000000003000000000000000100000000000000000000000000000020998ab035cb6d8387e90d418171ba07c9d56e07735e4f8cb63c9f5d782b860bc7000000000000000100000000000000010000000000000020a693b777a1b5cdf9e7f79e3c971f76ea7164d7e31bcecfe7381cf4ea3342445c000000000000000100000000000000010000000000000020f8ead15e9a227840dbfb08ca9ed87984de4763f5de50641ae9193ec8881985e90000000000000002000000000000000100000000000000200f044be55eca548bd7963cc4cfb11adb7a3b043c3f300c80eba0fdcc790035360000000000000004000000000000000100000000000000000000000000000020c6bb06cb7f92603de181bf256cd16846b93b752a170ff24824098b31aa008a7e0000000000000001000000000000000100000000000000206926cc6f9563da8fa6836177688ebfd52e3446c2e344d37949a222802a94eee70000000000000001000000000000000100000000000000205194a231165353123cbe4940bdbee3c1e726f8ed8ab5c6f5632d9353a2e8496d00000000000000010000000000000001000000000000002072697671d9683845d813b5b609a51e9e1c398b1ae9e2fecd065680155b0c6550000000000000000900000000000000200f044be55eca548bd7963cc4cfb11adb7a3b043c3f300c80eba0fdcc7900353600000000000000040000000000000001000000000000000000000000000000208a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b000000000000000100000000000000010000000000000020f30cd4b26a02d9e7718d60239f2256ee5ed5c5abfb059c08afa921df0b4cb30f0000000000000001000000000000000100000000000000204588fe9e87ee6f31163531890c67d678d24c4494821a1028f0f465520ff379e3000000000000000100000000000000000000000000000020ff58fff29fd22036c585d43655b2a2e930aaccffa097d22c96f45c4f101223c802341b1310b4dd47277804a47997784828d99a3555c0bbbe62e635a7d51f32f30000000000000020340e65a1d4528bd4a8ca97765eff0e5b95b51e0baf255176f6b7b707f95eae5900000000000000020334a5283db3d274f3af1786d36ef745afe16e4a823705ad8db657bc1671c2f713e973fe5ac040f6c01103060acfe512ad2d573af24d29b2524deb69617d98d700000000000000010000000000000020acc60cdc8d29be5a66d95632277cbf51c1871525f31d89fa35b6ddfe748973ce0000000000000002000000000000000100000000000000000000000000000020d45332e5b9b3c2aef6061517078322d0703e78ea0aa4b43e883ed381815e72ee0000000000000001000000000000000100000000000000202935a0176aa6e3e3c0a178383e6f9c7a5fc2fe2ef7dd2e68aea50f17e7e7d1a1000000000000000200000000000000010000000000000020340e65a1d4528bd4a8ca97765eff0e5b95b51e0baf255176f6b7b707f95eae590000000000000003000000000000000100000000000000000000000000000020998ab035cb6d8387e90d418171ba07c9d56e07735e4f8cb63c9f5d782b860bc7000000000000000100000000000000010000000000000020a693b777a1b5cdf9e7f79e3c971f76ea7164d7e31bcecfe7381cf4ea3342445c000000000000000100000000000000010000000000000020f8ead15e9a227840dbfb08ca9ed87984de4763f5de50641ae9193ec8881985e900000000000000050000000000000020340e65a1d4528bd4a8ca97765eff0e5b95b51e0baf255176f6b7b707f95eae5900000000000000030000000000000001000000000000000000000000000000209ae8f7e9f2dd92a357e9711e73b3caab3c3bcbe080cd1d24542667d5a4bb1918000000000000000100000000000000010000000000000020a1df989c31d035449e13902c13ad5902f211c96201153efdda7c74fe9f4b3b88000000000000000100000000000000000000000000000020ca0ad69fab8a3f1904afb1e30b4393706c607100b4f1b897463b4ae7f7fc56e519b8979cbfa7296adbfa67b64feea52196d3b61a3c6165f27390e4cab74bf4ee0000000000000020acc60cdc8d29be5a66d95632277cbf51c1871525f31d89fa35b6ddfe748973ce000000000000000202341b1310b4dd47277804a47997784828d99a3555c0bbbe62e635a7d51f32f32585c9c77f938cd7f67add0f5645ae76cc51e83160fbc9e59fe620651039d5480000000000000001000000000000002067dbb8c56baac607092baa212ad0d1a22deea771d736d8ab485d54f34d9c647400000000000000010000000000000001000000000000000000000000000000208b9a1498136a9fe584e1125d52f6a25b383feb7823fd84f8063e7f23b1c2acfb000000000000000200000000000000010000000000000020acc60cdc8d29be5a66d95632277cbf51c1871525f31d89fa35b6ddfe748973ce0000000000000002000000000000000100000000000000000000000000000020d45332e5b9b3c2aef6061517078322d0703e78ea0aa4b43e883ed381815e72ee0000000000000001000000000000000100000000000000202935a0176aa6e3e3c0a178383e6f9c7a5fc2fe2ef7dd2e68aea50f17e7e7d1a100000000000000030000000000000020acc60cdc8d29be5a66d95632277cbf51c1871525f31d89fa35b6ddfe748973ce00000000000000020000000000000001000000000000000000000000000000205a8fdd189ea47e6e243ffe0599772e70c5fdc9100fdb71455444a6cb5ba7920a00000000000000010000000000000000000000000000002063acc43c64829db93d053dc39c43abb44d352266e552c8b485ef04b7e62eeb2f149350a3f93911fe5cc82ac9c65d277638725f97e2c4a8967d6b56bb8f40760c000000000000002067dbb8c56baac607092baa212ad0d1a22deea771d736d8ab485d54f34d9c6474000000000000000219b8979cbfa7296adbfa67b64feea52196d3b61a3c6165f27390e4cab74bf4ee2e898308a309ccaf5682fd694d912507ab7dc25296517ea409690d745aa148a400000000000000000000000000000020d0713082ff7f000099385b0000000000eda00c13d58f80b4f8ffffffffffffff000000000000000000000000000000020000000000000001000000000000002067dbb8c56baac607092baa212ad0d1a22deea771d736d8ab485d54f34d9c647400000000000000010000000000000001000000000000000000000000000000208b9a1498136a9fe584e1125d52f6a25b383feb7823fd84f8063e7f23b1c2acfb0000000000000000000000000000002067dbb8c56baac607092baa212ad0d1a22deea771d736d8ab485d54f34d9c6474000000000000000100000000000000010000000000000001000000000000002073526e8c18933b8fcf96b8924370301f386abdf87e0ceaddae6d4d440721aa88";
        bytes memory init_blob = hex"00010203040506070809";
        types.transcript_data memory tr_state;
        transcript.init_transcript(tr_state, init_blob);
        types.fri_params_type memory params;
        params.modulus = modulus;
        params.r = 4;
        params.max_degree = 15;
        uint256[] memory D_omegas = new uint256[](params.r);
        D_omegas[0] = 14940766826517323942636479241147756311199852622225275649687664389641784935947;
        D_omegas[1] = 19540430494807482326159819597004422086093766032135589407132600596362845576832;
        D_omegas[2] = 21888242871839275217838484774961031246007050428528088939761107053157389710902;
        D_omegas[3] = 21888242871839275222246405745257275088548364400416034343698204186575808495616;
        params.D_omegas = D_omegas;
        uint256[] memory q = new uint256[](3);
        q[0] = 0;
        q[1] = 0;
        q[2] = 1;
        params.q = q;
        uint256[] memory U = new uint256[](1);
        U[0] = 0;
        uint256[] memory V = new uint256[](1);
        V[0] = 1;
        params.U = U;
        params.V = V;
        (types.fri_proof_type memory proof, uint256 proof_size) = fri_verifier.parse_proof_be(raw_proof, 0);
        Assert.equal(raw_proof.length, proof_size, "Proof length is not correct");
        bool result = fri_verifier.verifyProof(proof, tr_state, params);
        Assert.equal(true, result, "Proof is not correct");
        Assert.equal(raw_proof.length, fri_verifier.skip_proof_be(raw_proof, 0), "Skipping proof is not correct");
    }

    function test_fri_proof_raw_verification_d16() public {
        // bn254 scalar field
        uint256 modulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        bytes memory raw_proof = hex"0000000000000001149350a3f93911fe5cc82ac9c65d277638725f97e2c4a8967d6b56bb8f40760c00000000000000040334a5283db3d274f3af1786d36ef745afe16e4a823705ad8db657bc1671c2f700000000000000200f044be55eca548bd7963cc4cfb11adb7a3b043c3f300c80eba0fdcc7900353600000000000000020559201106e80dedf628230cd76d081bf8b42137cf2c9d6bb862f2fbcafd37a31278f47c764d688ed5ea487d2cd262139c57874aa1b1c5406e59ac5ae0597dba00000000000000010000000000000020340e65a1d4528bd4a8ca97765eff0e5b95b51e0baf255176f6b7b707f95eae590000000000000003000000000000000100000000000000000000000000000020998ab035cb6d8387e90d418171ba07c9d56e07735e4f8cb63c9f5d782b860bc7000000000000000100000000000000010000000000000020a693b777a1b5cdf9e7f79e3c971f76ea7164d7e31bcecfe7381cf4ea3342445c000000000000000100000000000000010000000000000020f8ead15e9a227840dbfb08ca9ed87984de4763f5de50641ae9193ec8881985e90000000000000002000000000000000100000000000000200f044be55eca548bd7963cc4cfb11adb7a3b043c3f300c80eba0fdcc790035360000000000000004000000000000000100000000000000000000000000000020c6bb06cb7f92603de181bf256cd16846b93b752a170ff24824098b31aa008a7e0000000000000001000000000000000100000000000000206926cc6f9563da8fa6836177688ebfd52e3446c2e344d37949a222802a94eee70000000000000001000000000000000100000000000000205194a231165353123cbe4940bdbee3c1e726f8ed8ab5c6f5632d9353a2e8496d00000000000000010000000000000001000000000000002072697671d9683845d813b5b609a51e9e1c398b1ae9e2fecd065680155b0c6550000000000000000900000000000000200f044be55eca548bd7963cc4cfb11adb7a3b043c3f300c80eba0fdcc7900353600000000000000040000000000000001000000000000000000000000000000208a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b000000000000000100000000000000010000000000000020f30cd4b26a02d9e7718d60239f2256ee5ed5c5abfb059c08afa921df0b4cb30f0000000000000001000000000000000100000000000000204588fe9e87ee6f31163531890c67d678d24c4494821a1028f0f465520ff379e3000000000000000100000000000000000000000000000020ff58fff29fd22036c585d43655b2a2e930aaccffa097d22c96f45c4f101223c802341b1310b4dd47277804a47997784828d99a3555c0bbbe62e635a7d51f32f30000000000000020340e65a1d4528bd4a8ca97765eff0e5b95b51e0baf255176f6b7b707f95eae5900000000000000020334a5283db3d274f3af1786d36ef745afe16e4a823705ad8db657bc1671c2f713e973fe5ac040f6c01103060acfe512ad2d573af24d29b2524deb69617d98d700000000000000010000000000000020acc60cdc8d29be5a66d95632277cbf51c1871525f31d89fa35b6ddfe748973ce0000000000000002000000000000000100000000000000000000000000000020d45332e5b9b3c2aef6061517078322d0703e78ea0aa4b43e883ed381815e72ee0000000000000001000000000000000100000000000000202935a0176aa6e3e3c0a178383e6f9c7a5fc2fe2ef7dd2e68aea50f17e7e7d1a1000000000000000200000000000000010000000000000020340e65a1d4528bd4a8ca97765eff0e5b95b51e0baf255176f6b7b707f95eae590000000000000003000000000000000100000000000000000000000000000020998ab035cb6d8387e90d418171ba07c9d56e07735e4f8cb63c9f5d782b860bc7000000000000000100000000000000010000000000000020a693b777a1b5cdf9e7f79e3c971f76ea7164d7e31bcecfe7381cf4ea3342445c000000000000000100000000000000010000000000000020f8ead15e9a227840dbfb08ca9ed87984de4763f5de50641ae9193ec8881985e900000000000000050000000000000020340e65a1d4528bd4a8ca97765eff0e5b95b51e0baf255176f6b7b707f95eae5900000000000000030000000000000001000000000000000000000000000000209ae8f7e9f2dd92a357e9711e73b3caab3c3bcbe080cd1d24542667d5a4bb1918000000000000000100000000000000010000000000000020a1df989c31d035449e13902c13ad5902f211c96201153efdda7c74fe9f4b3b88000000000000000100000000000000000000000000000020ca0ad69fab8a3f1904afb1e30b4393706c607100b4f1b897463b4ae7f7fc56e519b8979cbfa7296adbfa67b64feea52196d3b61a3c6165f27390e4cab74bf4ee0000000000000020acc60cdc8d29be5a66d95632277cbf51c1871525f31d89fa35b6ddfe748973ce000000000000000202341b1310b4dd47277804a47997784828d99a3555c0bbbe62e635a7d51f32f32585c9c77f938cd7f67add0f5645ae76cc51e83160fbc9e59fe620651039d5480000000000000001000000000000002067dbb8c56baac607092baa212ad0d1a22deea771d736d8ab485d54f34d9c647400000000000000010000000000000001000000000000000000000000000000208b9a1498136a9fe584e1125d52f6a25b383feb7823fd84f8063e7f23b1c2acfb000000000000000200000000000000010000000000000020acc60cdc8d29be5a66d95632277cbf51c1871525f31d89fa35b6ddfe748973ce0000000000000002000000000000000100000000000000000000000000000020d45332e5b9b3c2aef6061517078322d0703e78ea0aa4b43e883ed381815e72ee0000000000000001000000000000000100000000000000202935a0176aa6e3e3c0a178383e6f9c7a5fc2fe2ef7dd2e68aea50f17e7e7d1a100000000000000030000000000000020acc60cdc8d29be5a66d95632277cbf51c1871525f31d89fa35b6ddfe748973ce00000000000000020000000000000001000000000000000000000000000000205a8fdd189ea47e6e243ffe0599772e70c5fdc9100fdb71455444a6cb5ba7920a00000000000000010000000000000000000000000000002063acc43c64829db93d053dc39c43abb44d352266e552c8b485ef04b7e62eeb2f149350a3f93911fe5cc82ac9c65d277638725f97e2c4a8967d6b56bb8f40760c000000000000002067dbb8c56baac607092baa212ad0d1a22deea771d736d8ab485d54f34d9c6474000000000000000219b8979cbfa7296adbfa67b64feea52196d3b61a3c6165f27390e4cab74bf4ee2e898308a309ccaf5682fd694d912507ab7dc25296517ea409690d745aa148a400000000000000000000000000000020d0713082ff7f000099385b0000000000eda00c13d58f80b4f8ffffffffffffff000000000000000000000000000000020000000000000001000000000000002067dbb8c56baac607092baa212ad0d1a22deea771d736d8ab485d54f34d9c647400000000000000010000000000000001000000000000000000000000000000208b9a1498136a9fe584e1125d52f6a25b383feb7823fd84f8063e7f23b1c2acfb0000000000000000000000000000002067dbb8c56baac607092baa212ad0d1a22deea771d736d8ab485d54f34d9c6474000000000000000100000000000000010000000000000001000000000000002073526e8c18933b8fcf96b8924370301f386abdf87e0ceaddae6d4d440721aa88";
        bytes memory init_blob = hex"00010203040506070809";
        types.transcript_data memory tr_state;
        transcript.init_transcript(tr_state, init_blob);
        types.fri_params_type memory params;
        params.modulus = modulus;
        params.r = 4;
        params.max_degree = 15;
        uint256[] memory D_omegas = new uint256[](params.r);
        D_omegas[0] = 14940766826517323942636479241147756311199852622225275649687664389641784935947;
        D_omegas[1] = 19540430494807482326159819597004422086093766032135589407132600596362845576832;
        D_omegas[2] = 21888242871839275217838484774961031246007050428528088939761107053157389710902;
        D_omegas[3] = 21888242871839275222246405745257275088548364400416034343698204186575808495616;
        params.D_omegas = D_omegas;
        uint256[] memory q = new uint256[](3);
        q[0] = 0;
        q[1] = 0;
        q[2] = 1;
        params.q = q;
        uint256[] memory U = new uint256[](1);
        U[0] = 0;
        uint256[] memory V = new uint256[](1);
        V[0] = 1;
        params.U = U;
        params.V = V;
        (bool result1, uint256 proof_size1) = fri_verifier.parse_verify_proof_be(raw_proof, 0, tr_state, params);
        Assert.equal(true, result1, "Proof is not correct!");
        Assert.equal(raw_proof.length, proof_size1, "Proof length is not correct!");
        Assert.equal(raw_proof.length, fri_verifier.skip_proof_be(raw_proof, 0), "Skipping proof is not correct");
    }
}