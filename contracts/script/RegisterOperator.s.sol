// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";

import {IDelegationManager} from "@eigenlayer-contracts/src/contracts/interfaces/IDelegationManager.sol";
import {IKeyRegistrar} from "../lib/eigenlayer-middleware/src/interfaces/IKeyRegistrar.sol";

contract RegisterOperators is Script {
    // sepolia addresses
    IDelegationManager public DELEGATION_MANAGER = IDelegationManager(0xD4A7E1Bd8015057293f0D0A557088c286942e84b);
    function setUp() public {}

    function run() public {

        uint256 operatorPrivateKey = vm.envUint("OPERATOR_PRIVATE_KEY");
        address operatorAddress = vm.addr(operatorPrivateKey);
        string memory metdataUri = "";
        uint32 allocationDelay = 1;

        vm.startBroadcast(operatorPrivateKey);
        DELEGATION_MANAGER.registerAsOperator(
            address(0), // zero address for no specific operator set
            allocationDelay,
            metdataUri
        );
        vm.stopBroadcast();
    }
}
