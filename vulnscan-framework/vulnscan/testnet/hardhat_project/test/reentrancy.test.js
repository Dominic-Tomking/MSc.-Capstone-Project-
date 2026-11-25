// Reentrancy validation scenario (proposal S4.2.2).
// Deploys the victim, seeds it with honest deposits, deploys the attacker, and
// asserts that the bank is drained — the "exploit_confirmed" outcome.  Mirrors
// the PyEVM worker so results are comparable across backends.
const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Reentrancy validation", function () {
  it("drains the vulnerable bank (exploit_confirmed)", async function () {
    const [deployer, victim, attackerEOA] = await ethers.getSigners();

    const Bank = await ethers.getContractFactory("VulnerableBank");
    const bank = await Bank.deploy();
    await bank.waitForDeployment();

    await bank.connect(victim).deposit({ value: ethers.parseEther("5") });
    const before = await ethers.provider.getBalance(await bank.getAddress());

    const Attacker = await ethers.getContractFactory("ReentrancyAttacker");
    const attacker = await Attacker.deploy(await bank.getAddress());
    await attacker.waitForDeployment();

    await attacker.connect(attackerEOA).attack({ value: ethers.parseEther("1") });
    const after = await ethers.provider.getBalance(await bank.getAddress());

    console.log(`bank ${before} -> ${after}; hits=${await attacker.hits()}`);
    expect(after).to.be.lt(before);          // funds stolen -> exploit confirmed
  });
});
