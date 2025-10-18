/**
 * Migration script to deploy the EHRRegistry smart contract.
 */

// Import the contract artifact
const EHRRegistry = artifacts.require("EHRRegistry");

module.exports = function (deployer) {
  // Deploy the contract
  deployer.deploy(EHRRegistry);
};