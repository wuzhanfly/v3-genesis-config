const Web3 = require('web3'),
    fs = require('fs');

const ABI_STAKING = require('./build/abi/Staking.json');
const ABI_GOVERNANCE = require('./build/abi/Governance.json');


const STAKING_ADDRESS = '0x0000000000000000000000000000000000001000';
const SLASHING_INDICATOR_ADDRESS = '0x0000000000000000000000000000000000001001';
const SYSTEM_REWARD_ADDRESS = '0x0000000000000000000000000000000000001002';
const STAKING_POOL_ADDRESS = '0x0000000000000000000000000000000000007001';
const GOVERNANCE_ADDRESS = '0x0000000000000000000000000000000000007002';
const CHAIN_CONFIG_ADDRESS = '0x0000000000000000000000000000000000007003';
const RUNTIME_UPGRADE_ADDRESS = '0x0000000000000000000000000000000000007004';
const DEPLOYER_PROXY_ADDRESS = '0x0000000000000000000000000000000000007005';
const ALL_ADDRESSES = [
    STAKING_ADDRESS,
    SLASHING_INDICATOR_ADDRESS,
    SYSTEM_REWARD_ADDRESS,
    STAKING_POOL_ADDRESS,
    GOVERNANCE_ADDRESS,
    CHAIN_CONFIG_ADDRESS,
    // RUNTIME_UPGRADE_ADDRESS (runtime upgrade can't be upgraded)
    DEPLOYER_PROXY_ADDRESS,
];

const readByteCodeForAddress = address => {
    const artifactPaths = {
        [STAKING_ADDRESS]: './build/contracts/Staking.json',
        [SLASHING_INDICATOR_ADDRESS]: './build/contracts/SlashingIndicator.json',
        [SYSTEM_REWARD_ADDRESS]: './build/contracts/SystemReward.json',
        [STAKING_POOL_ADDRESS]: './build/contracts/StakingPool.json',
        [GOVERNANCE_ADDRESS]: './build/contracts/Governance.json',
        [CHAIN_CONFIG_ADDRESS]: './build/contracts/ChainConfig.json',
        [RUNTIME_UPGRADE_ADDRESS]: './build/contracts/RuntimeUpgrade.json',
        [DEPLOYER_PROXY_ADDRESS]: './build/contracts/DeployerProxy.json',
    }
    const filePath = artifactPaths[address]
    if (!filePath) throw new Error(`There is no artifact for the address: ${address}`)
    const {deployedBytecode} = JSON.parse(fs.readFileSync(filePath, 'utf8'))
    return deployedBytecode
}



