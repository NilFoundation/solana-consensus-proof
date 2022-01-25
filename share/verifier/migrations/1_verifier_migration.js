// const polynomian_eval = artifacts.require("polynomial");
const verification_keys = artifacts.require("verification_keys");
// const bn254_crypto = artifacts.require("bn254_crypto");
// const transcript = artifacts.require("transcript");
// const types = artifacts.require("types");
// const redshift_vk = artifacts.require("redshift_vk");
const verifier = artifacts.require("verifier");

module.exports = function (deployer) {
  // deployer.deploy(polynomian_eval);
  deployer.deploy(verification_keys);
  // deployer.deploy(bn254_crypto);
  // deployer.deploy(transcript);
  // deployer.deploy(types);
  // deployer.deploy(redshift_vk);
  deployer.link(verification_keys, verifier);
  deployer.deploy(verifier);
};
