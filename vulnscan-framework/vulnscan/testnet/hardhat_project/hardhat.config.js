/**
 * Hardhat configuration for the testnet validation backend.
 *
 * Runtime validation deploys contracts to the Hardhat Network (an in-process
 * Ethereum node) or, alternatively, to Foundry Anvil.  The Solidity version is
 * pinned for deterministic, reproducible validation (proposal S4.2.2).  Ganache
 * is retained only as a legacy comparison option.
 *
 * Inside the containerised service the solc compiler is fetched once at image
 * build time; the Python PyEVM backend (worker.py) is used where no compiler
 * download is available.
 */
require("@nomicfoundation/hardhat-toolbox");

module.exports = {
  solidity: {
    version: "0.8.19",
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  networks: {
    hardhat: { chainId: 31337, allowUnlimitedContractSize: true },
    anvil: { url: "http://127.0.0.1:8545" },
    // ganache: { url: "http://127.0.0.1:7545" }, // legacy comparison only
  },
  mocha: { timeout: 120000 },
};
