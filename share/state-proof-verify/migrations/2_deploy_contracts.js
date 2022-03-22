const verification_keys = artifacts.require("verification_keys");
const lpc_verifier = artifacts.require("lpc_verifier");

module.exports = function (deployer) {
  deployer.deploy(verification_keys);
  deployer.link(verification_keys, lpc_verifier);
  deployer.deploy(lpc_verifier);
};
