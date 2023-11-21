// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.0;

import "../InjectorContextHolder.sol";

contract StakingConfig is InjectorContextHolder, IStakingConfig {

    event ActiveValidatorsLengthChanged(uint32 prevValue, uint32 newValue);
    event CandidateLengthChanged(uint32 prevValue, uint32 newValue);
    event EpochBlockIntervalChanged(uint32 prevValue, uint32 newValue);
    event MisdemeanorThresholdChanged(uint32 prevValue, uint32 newValue);
    event FelonyThresholdChanged(uint32 prevValue, uint32 newValue);
    event ValidatorJailEpochLengthChanged(uint32 prevValue, uint32 newValue);
    event UndelegatePeriodChanged(uint32 prevValue, uint32 newValue);
    event MinValidatorStakeAmountChanged(uint256 prevValue, uint256 newValue);
    event MinStakingAmountChanged(uint256 prevValue, uint256 newValue);
    event MaxDelegateTotalAmountChanged(uint256 prevValue, uint256 newValue);
    event FinalityRewardRatioChanged(uint16 prevValue, uint16 newValue);

    struct StakingConfigSlot0 {
        uint32 activeValidatorsLength;
        uint32 candidateLength;
        uint32 epochBlockInterval;
        uint32 misdemeanorThreshold;
        uint32 felonyThreshold;
        uint32 validatorJailEpochLength;
        uint32 undelegatePeriod;
        uint256 minValidatorStakeAmount;
        uint256 minStakingAmount;
        uint256 maxDelegateTotalAmount;
        uint16 finalityRewardRatio;
    }

    StakingConfigSlot0 private _slot0;

    constructor(ConstructorArguments memory constructorArgs) InjectorContextHolder(constructorArgs) {
    }

    function initialize(
        uint32 activeValidatorsLength,
        uint32 candidateLength,
        uint32 epochBlockInterval,
        uint32 misdemeanorThreshold,
        uint32 felonyThreshold,
        uint32 validatorJailEpochLength,
        uint32 undelegatePeriod,
        uint256 minValidatorStakeAmount,
        uint256 minStakingAmount,
        uint256 maxDelegateTotalAmount,
        uint16 finalityRewardRatio
    ) external initializer {
        _slot0.activeValidatorsLength = activeValidatorsLength;
        emit ActiveValidatorsLengthChanged(0, activeValidatorsLength);
        _slot0.candidateLength = candidateLength;
        emit CandidateLengthChanged(0,candidateLength);
        _slot0.epochBlockInterval = epochBlockInterval;
        emit EpochBlockIntervalChanged(0, epochBlockInterval);
        _slot0.misdemeanorThreshold = misdemeanorThreshold;
        emit MisdemeanorThresholdChanged(0, misdemeanorThreshold);
        _slot0.felonyThreshold = felonyThreshold;
        emit FelonyThresholdChanged(0, felonyThreshold);
        _slot0.validatorJailEpochLength = validatorJailEpochLength;
        emit ValidatorJailEpochLengthChanged(0, validatorJailEpochLength);
        _slot0.undelegatePeriod = undelegatePeriod;
        emit UndelegatePeriodChanged(0, undelegatePeriod);
        _slot0.minValidatorStakeAmount = minValidatorStakeAmount;
        emit MinValidatorStakeAmountChanged(0, minValidatorStakeAmount);
        _slot0.minStakingAmount = minStakingAmount;
        emit MinStakingAmountChanged(0, minStakingAmount);
        _slot0.maxDelegateTotalAmount = maxDelegateTotalAmount;
        emit MaxDelegateTotalAmountChanged(0, minStakingAmount);
        _slot0.finalityRewardRatio = finalityRewardRatio;
        emit FinalityRewardRatioChanged(0, finalityRewardRatio);
    }


    function getConsensusParams() external view returns (StakingConfigSlot0 memory) {
        return _slot0;
    }

    function getActiveValidatorsLength() external view override returns (uint32) {
        return _slot0.activeValidatorsLength;
    }

    function setActiveValidatorsLength(uint32 newValue) external override onlyFromGovernance {
        uint32 prevValue = _slot0.activeValidatorsLength;
        _slot0.activeValidatorsLength = newValue;
        emit ActiveValidatorsLengthChanged(prevValue, newValue);
    }

    function getCandidateLength() external view override returns (uint32) {
        return _slot0.candidateLength;
    }

    function setCandidateLength(uint32 newValue) external override onlyFromGovernance {
        uint32 prevValue = _slot0.candidateLength;
        _slot0.candidateLength = newValue;
        emit CandidateLengthChanged(prevValue, newValue);
    }

    function getEpochBlockInterval() external view override returns (uint32) {
        return _slot0.epochBlockInterval;
    }

    function setEpochBlockInterval(uint32 newValue) external override onlyFromGovernance {
        uint32 prevValue = _slot0.epochBlockInterval;
        _slot0.epochBlockInterval = newValue;
        emit EpochBlockIntervalChanged(prevValue, newValue);
    }

    function getMisdemeanorThreshold() external view override returns (uint32) {
        return _slot0.misdemeanorThreshold;
    }

    function setMisdemeanorThreshold(uint32 newValue) external override onlyFromGovernance {
        uint32 prevValue = _slot0.misdemeanorThreshold;
        _slot0.misdemeanorThreshold = newValue;
        emit MisdemeanorThresholdChanged(prevValue, newValue);
    }

    function getFelonyThreshold() external view override returns (uint32) {
        return _slot0.felonyThreshold;
    }

    function setFelonyThreshold(uint32 newValue) external override onlyFromGovernance {
        uint32 prevValue = _slot0.felonyThreshold;
        _slot0.felonyThreshold = newValue;
        emit FelonyThresholdChanged(prevValue, newValue);
    }

    function getValidatorJailEpochLength() external view override returns (uint32) {
        return _slot0.validatorJailEpochLength;
    }

    function setValidatorJailEpochLength(uint32 newValue) external override onlyFromGovernance {
        uint32 prevValue = _slot0.validatorJailEpochLength;
        _slot0.validatorJailEpochLength = newValue;
        emit ValidatorJailEpochLengthChanged(prevValue, newValue);
    }

    function getUndelegatePeriod() external view override returns (uint32) {
        return _slot0.undelegatePeriod;
    }

    function setUndelegatePeriod(uint32 newValue) external override onlyFromGovernance {
        uint32 prevValue = _slot0.undelegatePeriod;
        _slot0.undelegatePeriod = newValue;
        emit UndelegatePeriodChanged(prevValue, newValue);
    }

    function getMinValidatorStakeAmount() external view returns (uint256) {
        return _slot0.minValidatorStakeAmount;
    }

    function setMinValidatorStakeAmount(uint256 newValue) external override onlyFromGovernance {
        uint256 prevValue = _slot0.minValidatorStakeAmount;
        _slot0.minValidatorStakeAmount = newValue;
        emit MinValidatorStakeAmountChanged(prevValue, newValue);
    }

    function getMinStakingAmount() external view returns (uint256) {
        return _slot0.minStakingAmount;
    }

    function setMinStakingAmount(uint256 newValue) external override onlyFromGovernance {
        uint256 prevValue = _slot0.minStakingAmount;
        _slot0.minStakingAmount = newValue;
        emit MinStakingAmountChanged(prevValue, newValue);
    }

    function getMaxDelegateTotalAmount() external view returns (uint256) {
        return _slot0.maxDelegateTotalAmount;
    }

    function setMaxDelegateTotalAmount(uint256 newValue) external override onlyFromGovernance {
        uint256 prevValue = _slot0.maxDelegateTotalAmount;
        _slot0.maxDelegateTotalAmount = newValue;
        emit MaxDelegateTotalAmountChanged(prevValue, newValue);
    }

    function getFinalityRewardRatio() external view returns (uint16) {
        return _slot0.finalityRewardRatio;
    }

    function setFinalityRewardRatio(uint16 newValue) external override onlyFromGovernance {
        uint16 prevValue = _slot0.finalityRewardRatio;
        _slot0.finalityRewardRatio = newValue;
        emit FinalityRewardRatioChanged(prevValue, newValue);
    }
}