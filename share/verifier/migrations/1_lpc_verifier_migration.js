const lpcVerifier = artifacts.require("lpc_verifier");

module.exports = function (deployer) {
  deployer.deploy(lpcVerifier);
};
