// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";

import {IDelegationManager} from "@eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import {IStrategy} from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import {IStrategyManager} from "@eigenlayer-contracts/src/contracts/interfaces/IStrategyManager.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IAllocationManager, IAllocationManagerTypes} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import {OperatorSet} from "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";

contract StakeAndDelegate is Script {
    // sepolia addresses
    IDelegationManager public DELEGATION_MANAGER = IDelegationManager(0xD4A7E1Bd8015057293f0D0A557088c286942e84b);
    IStrategy public STRATEGY_EIGEN = IStrategy(0x8E93249a6C37a32024756aaBd813E6139b17D1d5);
    IStrategyManager public STRATEGY_MANAGER = IStrategyManager(0x2E3D6c0744b10eb0A4e6F679F71554a39Ec47a5D);
    IERC20 public EIGEN_TOKEN = IERC20(0x0011FA2c512063C495f77296Af8d195F33A8Dd38);
    IAllocationManager public ALLOCATION_MANAGER = IAllocationManager(0x42583067658071247ec8CE0A516A58f682002d07);

    function setUp() public {}

    function run() public {
        uint256 stakerPrivateKey = vm.envUint("OPERATOR_PRIVATE_KEY");
        address stakerAddr = vm.addr(stakerPrivateKey);

        address avsAddress = vm.envAddress("AVS_ADDRESS");
        address operatorAddress = vm.envAddress("OPERATOR_ADDRESS");

        console.log("operatorAddress:", operatorAddress);
        
        (bool isSet, uint32 delay) = ALLOCATION_MANAGER.getAllocationDelay(operatorAddress);
        console.log("Is allocation delay set:", isSet);
        console.log("Allocation delay (in blocks):", delay);

        uint256 eigenBalance = EIGEN_TOKEN.balanceOf(stakerAddr);
        console.log("Eigen Token Balance:", eigenBalance);

        uint256 depositAmount = 1000000e18; // 1000 Eigen tokens

        vm.startBroadcast(stakerPrivateKey);
        EIGEN_TOKEN.approve(address(STRATEGY_MANAGER), depositAmount);

        // deposit 1000 Eigen tokens into the strategy
        STRATEGY_MANAGER.depositIntoStrategy(STRATEGY_EIGEN, EIGEN_TOKEN, depositAmount);
        // vm.stopBroadcast();

        // check deposit
        uint256 depositedAmount = STRATEGY_MANAGER.stakerDepositShares(stakerAddr, STRATEGY_EIGEN);

        OperatorSet memory opset0 = OperatorSet({avs: avsAddress, id: 0});

        IStrategy[] memory strategies = new IStrategy[](1);
        strategies[0] = STRATEGY_EIGEN;

        uint64[] memory mags = new uint64[](1);
        mags[0] = 1e18; // 1 Eigen token per share

        IAllocationManagerTypes.AllocateParams[] memory allocateParams = new IAllocationManagerTypes.AllocateParams[](1);

        allocateParams[0] = IAllocationManagerTypes.AllocateParams({
            operatorSet: opset0,
            strategies: strategies,
            newMagnitudes: mags
        });


        ALLOCATION_MANAGER.modifyAllocations(operatorAddress, allocateParams);
        // console.log("Staker deposit shares in STRATEGY_EIGEN:", depositedAmount);
        vm.stopBroadcast();
    }
}
