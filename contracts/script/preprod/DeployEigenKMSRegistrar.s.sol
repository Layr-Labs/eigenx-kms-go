// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {IAllocationManager} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import {IKeyRegistrar} from "@eigenlayer-contracts/src/contracts/interfaces/IKeyRegistrar.sol";
import {IPermissionController} from "@eigenlayer-contracts/src/contracts/interfaces/IPermissionController.sol";

import {EigenKMSRegistrar} from "../../src/EigenKMSRegistrar.sol";
import {IEigenKMSRegistrarTypes} from "../../src/interfaces/IEigenKMSRegistrar.sol";
import {OperatorSet} from "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";

contract DeployEigenKMSRegistrar is Script {
    // Eigenlayer Core Contracts
    IAllocationManager public ALLOCATION_MANAGER = IAllocationManager(0x42583067658071247ec8CE0A516A58f682002d07);
    IKeyRegistrar public KEY_REGISTRAR = IKeyRegistrar(0xA4dB30D08d8bbcA00D40600bee9F029984dB162a);
    IPermissionController public PERMISSION_CONTROLLER = IPermissionController(0x44632dfBdCb6D3E21EF613B0ca8A6A0c618F5a37); // TODO: Update with actual address

    function setUp() public {}

    function run(
        address avs,
        uint32 operatorSetId,
        address operator1,
        address operator2,
        address operator3
    ) public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY_DEPLOYER");

        vm.startBroadcast(deployerPrivateKey);
        console.log("Deployer address:", vm.addr(deployerPrivateKey));
        console.log("AVS address:", avs);
        console.log("Operator Set ID:", operatorSetId);

        // Create initial config
        IEigenKMSRegistrarTypes.AvsConfig memory initialConfig = IEigenKMSRegistrarTypes.AvsConfig({
            operatorSetId: operatorSetId
        });

        // Deploy ProxyAdmin
        ProxyAdmin proxyAdmin = new ProxyAdmin();
        console.log("ProxyAdmin deployed to:", address(proxyAdmin));

        // Deploy implementation
        EigenKMSRegistrar eigenKMSRegistrarImpl = new EigenKMSRegistrar(ALLOCATION_MANAGER, KEY_REGISTRAR, PERMISSION_CONTROLLER);
        console.log("EigenKMSRegistrar implementation deployed to:", address(eigenKMSRegistrarImpl));

        // Deploy proxy with initialization
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(eigenKMSRegistrarImpl),
            address(proxyAdmin),
            abi.encodeWithSelector(EigenKMSRegistrar.initialize.selector, avs, avs, initialConfig)
        );
        console.log("EigenKMSRegistrar proxy deployed to:", address(proxy));

        // Transfer ProxyAdmin ownership to avs
        proxyAdmin.transferOwnership(avs);
        vm.stopBroadcast();

        // Add operators to allowlist
        _addOperatorsToAllowlist(address(proxy), avs, operatorSetId, operator1, operator2, operator3);

        // Log final deployment summary
        console.log("\n=== Deployment Summary ===");
        console.log("ProxyAdmin:", address(proxyAdmin));
        console.log("Implementation:", address(eigenKMSRegistrarImpl));
        console.log("Proxy (use this address):", address(proxy));
        console.log("Owner:", avs);
        console.log("========================\n");
    }

    function _addOperatorsToAllowlist(
        address registrarProxy,
        address avs,
        uint32 operatorSetId,
        address operator1,
        address operator2,
        address operator3
    ) internal {
        uint256 avsPrivateKey = vm.envUint("PRIVATE_KEY_AVS");
        EigenKMSRegistrar registrar = EigenKMSRegistrar(registrarProxy);

        OperatorSet memory operatorSet = OperatorSet({
            avs: avs,
            id: operatorSetId
        });

        console.log("\nAdding operators to allowlist...");
        uint256 count = 0;

        vm.startBroadcast(avsPrivateKey);
        if (operator1 != address(0)) {
            registrar.addOperatorToAllowlist(operatorSet, operator1);
            console.log("Added operator 1:", operator1);
            count++;
        }
        if (operator2 != address(0)) {
            registrar.addOperatorToAllowlist(operatorSet, operator2);
            console.log("Added operator 2:", operator2);
            count++;
        }
        if (operator3 != address(0)) {
            registrar.addOperatorToAllowlist(operatorSet, operator3);
            console.log("Added operator 3:", operator3);
            count++;
        }

        console.log("Total operators allowlisted:", count);
        vm.stopBroadcast();
    }
}
