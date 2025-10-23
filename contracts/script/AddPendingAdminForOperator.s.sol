// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";

import { IPermissionController } from "@eigenlayer-contracts/src/contracts/interfaces/IPermissionController.sol";

contract AddPendingAdminForOperator is Script {
    // sepolia addresses
    IPermissionController public PERMISSION_CONTROLLER = IPermissionController(0x44632dfBdCb6D3E21EF613B0ca8A6A0c618F5a37);
    function setUp() public {}

    function run(address admin) public {
        uint256 operatorPrivateKey = vm.envUint("OPERATOR_PRIVATE_KEY");
        // get address from privateKey
        address operator = vm.addr(operatorPrivateKey);

        vm.startBroadcast(operatorPrivateKey);
        PERMISSION_CONTROLLER.addPendingAdmin(
            operator,
            admin
        );

        vm.stopBroadcast();
    }
}
