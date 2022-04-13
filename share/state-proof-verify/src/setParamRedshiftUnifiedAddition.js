const myModule = require('./main.js');
const fs = require('fs');

const contract_data = JSON.parse(
    fs.readFileSync("TestRedshiftVerifierUnifiedAddition.json")
);


// var adress = generateAddressesFromSeed(mnemonic, 1);

// var contract = new web3.eth.Contract(contract_data.abi, "0x2ab4343f34cd01088af926b436bd7043e7945fbe");
// new
var contract = new myModule.web3.eth.Contract(contract_data.abi, "0x8EFde6959Bc5CA35A8C26221de6aa8d732877df9");


myModule.signTransaction(contract.methods.set_q([0, 0, 1]).encodeABI());

myModule.signTransaction(contract.methods.set_initial_params(
    new BN('40000000000000000000000000000000224698fc094cf91b992d30ed00000001', 16),
    1,
    3,
    1,
    2,
    4,
    new BN('24760239192664116622385963963284001971067308018068707868888628426778644166363', 10),
    13
).encodeABI());

myModule.signTransaction(contract.methods.set_D_omegas([new BN('24760239192664116622385963963284001971067308018068707868888628426778644166363', 10),]).encodeABI(), adress[0]);

for (var i = 0; i < 13; i++) {
    myModule.signTransaction(contract.methods.set_column_rotations([0,], i).encodeABI());
}

myModule.signTransaction(contract.methods.set_column_rotations([0,], 1).encodeABI());
