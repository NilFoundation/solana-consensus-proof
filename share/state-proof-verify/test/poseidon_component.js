const BN = require('bn.js');
const TestComponent = artifacts.require("TestPoseidonComponent");

contract("Poseidon component evaluation", accounts => {
    it("Case 1", async () => {
        const instance = await TestComponent.deployed();
        await instance.set_params(
            new BN('40000000000000000000000000000000224698fc094cf91b992d30ed00000001', 16),
            new BN('28867777448171893195754124589869130277690340596632500575713534438442847395049', 10)
        );
        await instance.evaluate('0x384735a86ee93e04d3242fc5228b2ce9fd3e993438a1bd1533a353e4d4119dd214d3a2b5f523172acfe643de27d847be67f490954aae95c009b99438c11c5c5431e04d7af0423d77e7c90ce7acd5edfdba5f9e2812e8eee81e09806d784d8f023cf3c7122e77c64e1fee23ce6f7d74780419a46499cd1038b206117cd2f671090c73d4746c687a3fdb99ab46bd9e0efb1e863c8a6c0eebd16bcde18bf128e7cb3c394f3ccf42dd69433f3c9e95b14605fdc40434886ff24dcf84162d624919af0028cd976c20691c9e7afc053d24552c7d2048a7257a08a2221b63678cdae6de3b3f4a7b8801c00fce60ab7e085cd02f3e93b54fa466ce03937ef7565faf4b630906694ce26a8cc75d5ed181a8a686e3b6600154078ebe6087b76dc184c9c7f7204f397f2e6fe84e18fef23b2f475d3c35bbf3c77c0f9aa75054b549cdd86d5d14c05e8da6913089133cba76f7da669a63b324d6dbac013ce40c6efa08004b363be4645e08fbc6bba8a6107af780bfd8dd7114b9ba1841f78a4ac132574d6bbe0b3736fe2dc951852d4383f4bcfec97617a4394b414956f2fcdef66bbe87984422a7c3584193bb3690aea95f3c8b875022a60ec90c97580972f254e97f8aeeb9126d356291b372f82944eab4fe6031fdcaec7d24bea32ed7a185e1e73a3914a8228ae72c2f3ffd8ea2a3979768f8cfe01303db9bb7fcdaeca9e43cfe7a2c120c2c3d94ae2c52260224b98def5e57281cf428f9084ce960df19a2d982b16f058c271d3d8d411cd5bdabe0ae8f94e33765921b4f3ec87d476af0fbce55d489942d3179fdaf5435b81b75b73f0ab9ea14af50d18cc8ccc13bc571389d33db56cbbc0a88991d306ff89b412945ebb01724b97b765e196a75cb30a1c6b260e4c107cd2be4c8eea9de54890e4e5e7574a1a72d829148af7d5a75e26c30027c8ae1d32d0323409b13441113bd457d669977dc8dd5bae36af884e841c43b0cd96b0fabb7287de057ad7f285ccedce31b35e8edc1228d1350802b18e34d96fef4d857896d1945275b26affd03451d96460dbc6eef885b182e6311d24a830cc1d9ff28099c3e9d4f8e0292296083e71b6cbf36cf578967bfddc0650b8f7709ad0b9648910b30a7f2be344b0465115da913e015b75a3bf5339b174fd1a4ce5e9853796152311d1272df215484713283dfbf9874ea486693532bc519da618d0248e6f82493583fce7d220948d155efa7316c26f17048c3003cdc7969207b3d58a708871e5c003a83506a5c66971a2f05f81c42b01e8a461fca9a16943ede984af205cfdfaa59');
        const evaluation_result = await instance.m_evaluation_result();
        assert.equal(
            evaluation_result.toString(10),
            '25233477192336665037682527985858566183353043495248649287999569848108177051602',
            'Gate evaluation result is not correct!'
        );
        const theta_acc_result = await instance.m_theta_acc();
        assert.equal(
            theta_acc_result.toString(10),
            '1976499999820661819552539332832698425856485160547217699694454629109744347131',
            'Theta accumulator result is not correct!'
        );
    });

    it("Case 2", async () => {
        const instance = await TestComponent.deployed();
        await instance.set_params(
            new BN('40000000000000000000000000000000224698fc094cf91b992d30ed00000001', 16),
            new BN('15642692033521821362943598523045789528868899296190229489727190434267390302812', 10)
        );
        await instance.evaluate('0x1d9b5e4b261bd21f20d6d2f1a6c97cddb2147e8c8b333b23de363f5215e1bd5c08317e087aaa36b5f70893acd1b8ea9846f20eb94548ab2bb3934ebcb6be30683e1a0a2dc82ce8fd111f3a325cce34c81696d6977254f0ef67866aed3ddd8b0239e2a3bebcf2f02a456b8f5dd6a2a8800ee9bfc266c408950ce449ae5ec283ae32f04e4dbef867b23cc5848704af6dd7ad84e0f3dcc0656dae5aa6bd8de3ef1a1ffb5d2fcd0b6db0dc4ebc00ff45969401ef86a855eb81fdd31e1d039324a6be2b3c065a61885b518525c427ab7509e878b08706256df7bcaf430e8fc427fbac0d09102389986c4394d1cb2f4a11fae1a23ba826dc049db464bdf6d125b949f5244a8af0ae1a83eff133c35d9c20a72f0cd8bae76799a560fbe0354aa47e252b0ee834f2b43cbefeda4c42d3ac98c308187b8cd9d75a57ad88ee2a434c40112923be145a148c0075f0cc9950a64f27e345b377df6657f903eb41f1465a1005203d0eadbe30678beaf578de2d2e3583b76d869f1c7988d837975c48a112e5277f2cd53899f428a98561cb1dea73b8f5a4f32470bac14f828666dd404c843096d822dff0f0790d5952e335dea3491fc7090aa549145f7109e4bef115f09fa6ca6417f914422b6fe7f858af583fb11e1767989cc0299e655c5291311d92b48290550ae84e08706c10d2b87d1e29e5372b506d264b1691725762651aa4b5dabda9d736e305ccaf4dd21f702cadd14f22af3e97e6e30b3c7592454aea9abf1f6b4d6f3889cb8507c78b78a1335d70a93559b1730ff45729063389fa069b9a296cc2271db1735f73fb56fd52200b4435af8d80da9a3c73de8238c04a799e4b07b5f23f0adbf69d33adae316ee3bcc309976209cc827449ca03e90ab020630069edc9d122322f3d7c85ee0b1dd603bbda19b11baadb77548974dedfb171022fb25ccb040e92326dcf6eee8986bbc7cbd8f27a8bc13e6e6519c75d3fff39c8d0fa22b72737542d0c24d4c1160c54cc522ca2fe632fcc5e231baa5de240f4b848aaec64942454ba835883f4eb8f74fb0e7fbc5ec47b7d0fc65bec1df853c2d270fd81fb48171f65e9f6bbb501f77c5aa2c21e286cd48b54cec12f9764727bfcade336ca253728ce2c46f00775241b17629298678594039817b142df1841f366c0ed7e0b5726167386ab29b1a9eb59eb946947ce0128755f7a79d9fdd2db1d97de2770bd283858a9f41bae31b4dfeac68cf0c265d4a55018d706c34f94d82a0856f3839f42134860a8f6e444d0f3a088601bc2ff5c40566ddc0ba380a8e557cc813d0d7775');
        const evaluation_result = await instance.m_evaluation_result();
        assert.equal(
            evaluation_result.toString(10),
            '2126503404489425890341855054747453817199607483149302586937783395130950629939',
            'Gate evaluation result is not correct!'
        );
        const theta_acc_result = await instance.m_theta_acc();
        assert.equal(
            theta_acc_result.toString(10),
            '13274050904598753556730543251655570580716885683276761834879891133334710178752',
            'Theta accumulator result is not correct!'
        );
    });
});
