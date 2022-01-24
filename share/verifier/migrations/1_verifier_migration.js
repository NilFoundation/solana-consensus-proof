const verifier = artifacts.require("verifier");

module.exports = function (deployer) {
  deployer.deploy(verifier);
};
