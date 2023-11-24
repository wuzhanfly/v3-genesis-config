// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.0;

import "./libs/StakingValidatorRegistry.sol";
import "./libs/StakingRewardDistribution.sol";
import "./libs/RetriableProxy.sol";

/**
 * You might ask why this library model is so overcomplicated... the answer is that we tried
 * to keep backward compatibility with existing storage layout when smart contract size become more than 24kB.
 *
 * Since this checks works only for deployed smart contracts (not constructors) then we can deploy several
 * smart contracts with more than 24kB size.
 */
contract Staking is StakingStorageLayout, RetryableProxy  {

    StakingValidatorRegistry private immutable _validatorRegistryLib;
    StakingRewardDistribution private immutable _rewardDistributionLib;

    constructor(
        IStaking stakingContract,
        ISlashingIndicator slashingIndicatorContract,
        ISystemReward systemRewardContract,
        IStakingPool stakingPoolContract,
        IGovernance governanceContract,
        IChainConfig chainConfigContract,
        IRuntimeUpgrade runtimeUpgradeContract,
        IDeployerProxy deployerProxyContract
    ) InjectorContextHolder(
        stakingContract,
        slashingIndicatorContract,
        systemRewardContract,
        stakingPoolContract,
        governanceContract,
        chainConfigContract,
        runtimeUpgradeContract,
        deployerProxyContract
    ) {
        _validatorRegistryLib = new StakingValidatorRegistry(stakingContract,
            slashingIndicatorContract,
            systemRewardContract,
            stakingPoolContract,
            governanceContract,
            chainConfigContract,
            runtimeUpgradeContract,
            deployerProxyContract);
        _rewardDistributionLib = new StakingRewardDistribution(stakingContract,
            slashingIndicatorContract,
            systemRewardContract,
            stakingPoolContract,
            governanceContract,
            chainConfigContract,
            runtimeUpgradeContract,
            deployerProxyContract);
    }

    function initialize(address[] calldata validators, address[] calldata owners, uint256[] calldata initialStakes, uint16 commissionRate) external initializer {
        require(validators.length == owners.length && validators.length == initialStakes.length);
        uint256 totalStakes = 0;
        for (uint256 i = 0; i < validators.length; i++) {
            _addValidator(validators[i], owners[i], ValidatorStatus.Active, commissionRate, initialStakes[i], 0);
            totalStakes += initialStakes[i];
        }
        require(address(this).balance == totalStakes);
    }

    function _fallback() internal virtual override {
        // try both of addresses
        _delegate(address(_validatorRegistryLib));
        _delegate(address(_rewardDistributionLib));
        // revert if not found
        revert MethodNotFound();
    }
}
