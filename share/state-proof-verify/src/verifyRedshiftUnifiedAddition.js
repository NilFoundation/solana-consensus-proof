const myModule = require('./main.js');
const fs = require("fs");

function verifyRedshiftUnifiedAddition(proof) {
    const contract_data = JSON.parse(
        fs.readFileSync("TestRedshiftVerifierUnifiedAddition.json")
    );

    contractAdress = contract_data.networks["3"].address;
    contractAbi = contract_data.abi;

    x = myModule.sendProof(contractAdress, contractAbi, proof);
    x.then(result => {
        if (result === true) {
            console.log("Verified");
            return "Verified!";
        } else {
            console.log("Error verified");
            return "Error verified!";
        }
    });
}

const { performance } = require('perf_hooks');

var startTime = performance.now()

var text = fs.readFileSync(0).toString('utf-8').trim();

verifyRedshiftUnifiedAddition(text);

var endTime = performance.now()

fs.appendFileSync('time.log', 'redshift-unified-addition: ' + Math.trunc(endTime - startTime).toString() + 'ms\n');
