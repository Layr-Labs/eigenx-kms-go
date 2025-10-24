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

contract DeployEigenKMSRegistrar is Script {
    // Eigenlayer Core Contracts
    IAllocationManager public ALLOCATION_MANAGER = IAllocationManager(0x42583067658071247ec8CE0A516A58f682002d07);
    IKeyRegistrar public KEY_REGISTRAR = IKeyRegistrar(0xA4dB30D08d8bbcA00D40600bee9F029984dB162a);
    IPermissionController public PERMISSION_CONTROLLER = IPermissionController(0x44632dfBdCb6D3E21EF613B0ca8A6A0c618F5a37); // TODO: Update with actual address

    function setUp() public {}

    function run(
        address avs
    ) public {
        // Load the private key from the environment variable
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY_DEPLOYER");
        address deployer = vm.addr(deployerPrivateKey);

        // 1. Deploy the EigenKMSRegistrar middleware contract
        vm.startBroadcast(deployerPrivateKey);
        console.log("Deployer address:", deployer);

        // Create initial config
        IEigenKMSRegistrarTypes.AvsConfig memory initialConfig = IEigenKMSRegistrarTypes.AvsConfig({
            operatorSetId: 1
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

        // Transfer ProxyAdmin ownership to avs (or a multisig in production)
        proxyAdmin.transferOwnership(avs);

        vm.stopBroadcast();
    }
}
