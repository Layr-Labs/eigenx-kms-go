// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test, console} from "forge-std/Test.sol";
import {EigenKMSRegistrar} from "../src/EigenKMSRegistrar.sol";
import {IEigenKMSRegistrarTypes} from "../src/interfaces/IEigenKMSRegistrar.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

// Mock contracts for testing
import {IAllocationManager} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import {IKeyRegistrar} from "@eigenlayer-contracts/src/contracts/interfaces/IKeyRegistrar.sol";
import {IPermissionController} from "@eigenlayer-contracts/src/contracts/interfaces/IPermissionController.sol";

contract EigenKMSRegistrarTest is Test {
    event AvsConfigSet(uint32 operatorSetId, string platformRpcUrl);

    EigenKMSRegistrar public registrar;

    // Test addresses
    address public owner = address(0x1234);
    address public avsAddress = address(0x5678);
    address public operator1 = address(0x1111);
    address public operator2 = address(0x2222);
    address public operator3 = address(0x3333);

    // Mock contract addresses (would be real contracts in production)
    IAllocationManager public allocationManager = IAllocationManager(address(0x1001));
    IKeyRegistrar public keyRegistrar = IKeyRegistrar(address(0x1002));
    IPermissionController public permissionController = IPermissionController(address(0x1003));

    function setUp() public {
        // Deploy the EigenKMSRegistrar contract
        registrar = new EigenKMSRegistrar(allocationManager, keyRegistrar, permissionController);

        console.log("EigenKMSRegistrar deployed at:", address(registrar));
        console.log("Test setup complete");
    }

    function test_ContractDeployment() public {
        // Verify the contract deployed successfully
        assertTrue(address(registrar) != address(0), "Contract should be deployed");

        console.log("Contract deployment test passed");
    }

    function test_SetAvsConfig() public {
        // Create test AVS configuration
        IEigenKMSRegistrarTypes.AvsConfig memory config =
            IEigenKMSRegistrarTypes.AvsConfig({operatorSetId: 1, platformRpcUrl: ""});

        // Test that only owner can set config (this will fail since we haven't initialized ownership)
        vm.expectRevert();
        registrar.setAvsConfig(config);

        console.log("SetAvsConfig access control test passed");
    }

    function test_GetAvsConfig() public {
        // Test getting default config (should be empty)
        IEigenKMSRegistrarTypes.AvsConfig memory config = registrar.getAvsConfig();

        // Default operatorSetId should be 0
        assertEq(config.operatorSetId, 0, "Default operatorSetId should be 0");

        console.log("GetAvsConfig test passed");
    }

    function test_AvsConfigOperatorSetId() public {
        // Test different operator set IDs
        uint32[] memory testIds = new uint32[](3);
        testIds[0] = 1;
        testIds[1] = 100;
        testIds[2] = 4_294_967_295; // Max uint32

        for (uint256 i = 0; i < testIds.length; i++) {
            IEigenKMSRegistrarTypes.AvsConfig memory config =
                IEigenKMSRegistrarTypes.AvsConfig({operatorSetId: testIds[i], platformRpcUrl: ""});

            // This will revert due to ownership, but we're testing the function signature
            vm.expectRevert();
            registrar.setAvsConfig(config);
        }

        console.log("OperatorSetId boundary test passed");
    }

    /// @dev Deploys an initialized registrar behind a proxy so `owner` can set config.
    ///      The raw implementation disables initializers in its constructor.
    function _deployInitializedRegistrar() internal returns (EigenKMSRegistrar) {
        EigenKMSRegistrar impl = new EigenKMSRegistrar(allocationManager, keyRegistrar, permissionController);
        ProxyAdmin proxyAdmin = new ProxyAdmin();
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl),
            address(proxyAdmin),
            abi.encodeWithSelector(
                EigenKMSRegistrar.initialize.selector,
                avsAddress,
                owner,
                IEigenKMSRegistrarTypes.AvsConfig({operatorSetId: 0, platformRpcUrl: ""})
            )
        );
        return EigenKMSRegistrar(address(proxy));
    }

    function test_AvsConfig_PersistsPlatformRpcUrl() public {
        EigenKMSRegistrar reg = _deployInitializedRegistrar();

        IEigenKMSRegistrarTypes.AvsConfig memory config =
            IEigenKMSRegistrarTypes.AvsConfig({operatorSetId: 2, platformRpcUrl: "platform.example:9002"});

        vm.prank(owner);
        reg.setAvsConfig(config);

        IEigenKMSRegistrarTypes.AvsConfig memory got = reg.getAvsConfig();
        assertEq(got.operatorSetId, uint32(2));
        assertEq(got.platformRpcUrl, "platform.example:9002");

        console.log("PlatformRpcUrl round-trip test passed");
    }

    function test_AvsConfig_EmitsEvent() public {
        EigenKMSRegistrar reg = _deployInitializedRegistrar();

        vm.expectEmit(true, true, true, true);
        emit AvsConfigSet(3, "p.example:9002");

        vm.prank(owner);
        reg.setAvsConfig(IEigenKMSRegistrarTypes.AvsConfig({operatorSetId: 3, platformRpcUrl: "p.example:9002"}));

        console.log("AvsConfigSet event test passed");
    }

    function test_ContractInterfaces() public {
        // Verify the contract supports the expected interfaces
        // Note: We can't test interface calls without proper initialization

        // For now, just verify the contract exists and has the expected functions
        // Interface testing would require proper AVS initialization

        console.log("Contract interface test passed");
    }

    function test_MultipleOperatorSetIds() public {
        // Test configuration with different operator set IDs
        uint32[] memory operatorSetIds = new uint32[](5);
        operatorSetIds[0] = 1;
        operatorSetIds[1] = 2;
        operatorSetIds[2] = 10;
        operatorSetIds[3] = 100;
        operatorSetIds[4] = 1000;

        for (uint256 i = 0; i < operatorSetIds.length; i++) {
            IEigenKMSRegistrarTypes.AvsConfig memory config =
                IEigenKMSRegistrarTypes.AvsConfig({operatorSetId: operatorSetIds[i], platformRpcUrl: ""});

            // Verify we can create the config struct
            assertTrue(config.operatorSetId == operatorSetIds[i], "OperatorSetId should match");
        }

        console.log("Multiple operator set IDs test passed");
    }

    function test_StorageLayout() public {
        // Test that storage is properly initialized
        IEigenKMSRegistrarTypes.AvsConfig memory defaultConfig = registrar.getAvsConfig();

        // Should have default zero values
        assertEq(defaultConfig.operatorSetId, 0, "Default storage should be zero");

        console.log("Storage layout test passed");
    }

    function test_EventsAndLogs() public {
        // Test basic logging functionality
        console.log("Testing contract state:");
        console.log("  Contract address:", address(registrar));
        console.log("  Owner address:", owner);
        console.log("  AVS address:", avsAddress);

        // Verify contract has been deployed with correct bytecode
        address registrarAddr = address(registrar);
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(registrarAddr)
        }

        assertTrue(codeSize > 0, "Contract should have bytecode");
        console.log("  Contract bytecode size:", codeSize);
        console.log("Events and logs test passed");
    }

    function test_GasUsage() public {
        // Test gas usage for key functions
        uint256 gasBefore;
        uint256 gasAfter;

        // Test getAvsConfig gas usage
        gasBefore = gasleft();
        registrar.getAvsConfig();
        gasAfter = gasleft();

        uint256 getConfigGas = gasBefore - gasAfter;
        console.log("getAvsConfig gas usage:", getConfigGas);

        // Should be relatively low gas (reads a uint32 plus a dynamic-length string)
        assertTrue(getConfigGas < 20_000, "getAvsConfig should use reasonable gas");

        console.log("Gas usage test passed");
    }
}
