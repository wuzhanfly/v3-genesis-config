// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.0;

interface ISystemReward {

    function getSystemReward(address user, uint256 epoch) external view returns (uint256);

    function withdrawRewards(uint256 epoch) external;

    function withdrawMultipleEpochRewards(uint256[] calldata epochs) external;
}