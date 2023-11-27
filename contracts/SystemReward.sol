// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.0;

import "./Injector.sol";

import "@openzeppelin/contracts/utils/Address.sol";

contract SystemReward is ISystemReward, InjectorContextHolder {

    // Epoch > _systemFee
    mapping(uint256 =>uint256 ) internal  _systemFeeMap ;
    // Epoch => user => Reward
    mapping(uint256 => mapping(address => uint256)) private _rewardSnapshotMap;

    event WithdrawSystemRewards(address indexed validator,uint256 amount, uint256 epoch);

    event WithdrawMultipleEpochSystemRewards(address indexed validator,uint256 amount, uint256[]  epochs);

    constructor(bytes memory constructorParams) InjectorContextHolder(constructorParams) {
    }
    function ctor(address[] calldata accounts, uint16[] calldata shares) external onlyInitializing {
    }

    receive() external payable {
//        require(msg.sender == address(_stakingContract),"address is not staking address");
        // increase total system fee
        uint256 currentEpoch  = _stakingContract.currentEpoch();
        _systemFeeMap[currentEpoch] = address(this).balance;
    }

    function updateReward(address user, uint256 epoch, uint256 rewardAmount) internal {
        _rewardSnapshotMap[epoch][user] += rewardAmount;
    }



    function getUserStakedAtEpoch(address user, uint256 epoch) internal view returns (uint256) {
        uint256 totalStaked = 0;
        address[] memory validators = _stakingContract.getAllValidators();

        for (uint256 i = 0; i < validators.length; i++) {
            (uint256 stakedAmount, uint64 stakedEpoch) = _stakingContract.getValidatorDelegation(validators[i], user);
            if (stakedEpoch <= epoch) {
                totalStaked += stakedAmount;
            }
        }
        return totalStaked;
    }
    function getTotalStakedAtEpoch(uint256 epoch) internal view returns (uint256) {
        uint256 totalStaked = 0;
        address[] memory validators = _stakingContract.getAllValidators();
        for (uint256 i = 0; i < validators.length; i++) {
            address validator = validators[i];
            (, , uint256 totalDelegated, , , , , , ) = _stakingContract.getValidatorStatusAtEpoch(validator, uint64(epoch));
            totalStaked += totalDelegated;
        }
        return totalStaked;
    }

    function calculateAndUpdateUserReward(address user, uint256 epoch) public {
        uint256 totalStaked = getTotalStakedAtEpoch(epoch);
        uint256 userStaked = getUserStakedAtEpoch(user, epoch);
        uint256 totalReward = _systemFeeMap[epoch];
        if (totalStaked > 0) {
            uint256 userReward = (userStaked * totalReward) / totalStaked;
            updateReward(user, epoch, userReward);
        }
    }

    function getSystemReward(address user, uint256 epoch) public view returns (uint256) {
        uint256 totalStaked = getTotalStakedAtEpoch(epoch);
        uint256 userStaked = getUserStakedAtEpoch(user, epoch);
        uint256 totalReward = _systemFeeMap[epoch];
        if (totalStaked == 0) return 0;
        return (userStaked * totalReward) / totalStaked;
    }

    function withdrawMultipleEpochRewards(uint256[] calldata epochs) external {
        uint256 totalReward = 0;
        uint256 currentEpoch  = _stakingContract.currentEpoch();
        for (uint i = 0; i < epochs.length; i++) {
            uint256 epoch = epochs[i];
            require(epoch < currentEpoch ,"epoch is too height");
            uint256 reward = _rewardSnapshotMap[epoch][msg.sender];
            if (reward > 0) {
                totalReward += reward;
                _rewardSnapshotMap[epoch][msg.sender] = 0;
            }
        }

        require(totalReward > 0, "No rewards available");

        // 安全地转移奖励给用户
        (bool success, ) = msg.sender.call{value: totalReward}("");
        require(success, "Reward transfer failed");
        emit WithdrawMultipleEpochSystemRewards(msg.sender,totalReward,epochs);

    }

    function withdrawRewards(uint256 epoch) external {
        uint256 currentEpoch  = _stakingContract.currentEpoch();
        require(epoch < currentEpoch ,"epoch is too height");
        calculateAndUpdateUserReward(msg.sender, epoch);

        uint256 reward = _rewardSnapshotMap[epoch][msg.sender];
        require(reward > 0, "No rewards available");
        _rewardSnapshotMap[epoch][msg.sender] = 0;

        // 安全地转移奖励给用户
        (bool success, ) = msg.sender.call{value: reward}("");
        require(success, "Reward transfer failed");
        emit WithdrawSystemRewards(msg.sender,reward,epoch);
    }
}