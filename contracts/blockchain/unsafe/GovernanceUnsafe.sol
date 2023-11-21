// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.0;

import "../Governance.sol";

contract GovernanceUnsafe is Governance {

    constructor(ConstructorArguments memory constructorArgs) Governance(constructorArgs) {
    }

    modifier onlyFromCoinbase() override {
        _;
    }

    modifier onlyFromSlashingIndicator() override {
        _;
    }

    modifier onlyFromGovernance() override {
        _;
    }

    modifier onlyBlock(uint64 /*blockNumber*/) override {
        _;
    }
}