// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";

import {
    IAllocationManager,
    IAllocationManagerTypes
} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import {IAVSRegistrar} from "@eigenlayer-contracts/src/contracts/interfaces/IAVSRegistrar.sol";
import {IStrategy} from "@eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import {IKeyRegistrar, IKeyRegistrarTypes} from "@eigenlayer-contracts/src/contracts/interfaces/IKeyRegistrar.sol";
import {OperatorSet} from "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import { IReleaseManager } from "@eigenlayer-contracts/src/contracts/interfaces/IReleaseManager.sol";

contract SetupEigenKMSRegistrar is Script {
    // Eigenlayer Core Contracts
    IAllocationManager public ALLOCATION_MANAGER = IAllocationManager(0x42583067658071247ec8CE0A516A58f682002d07);
    IKeyRegistrar constant KEY_REGISTRAR = IKeyRegistrar(0xA4dB30D08d8bbcA00D40600bee9F029984dB162a);
    IReleaseManager public RELEASE_MANAGER = IReleaseManager(0x59c8D715DCa616e032B744a753C017c9f3E16bf4);

    // Eigenlayer Strategies
    IStrategy public STRATEGY_WETH = IStrategy(0x424246eF71b01ee33aA33aC590fd9a0855F5eFbc);

    function setUp() public {}

    function run(
        address eigenKmsRegistrar
    ) public {
        // Load the private key from the environment variable
        uint256 avsPrivateKey = vm.envUint("PRIVATE_KEY_AVS");
        address avs = vm.addr(avsPrivateKey);

        vm.startBroadcast(avsPrivateKey);
        console.log("AVS address:", avs);

        // 1. Update the AVS metadata URI
        ALLOCATION_MANAGER.updateAVSMetadataURI(avs, "EigenX KMS");
        console.log("AVS metadata URI updated: EigenX KMS");

        // 2. Set the AVS Registrar
        ALLOCATION_MANAGER.setAVSRegistrar(avs, IAVSRegistrar(eigenKmsRegistrar));
        console.log("AVS Registrar set:", address(ALLOCATION_MANAGER.getAVSRegistrar(avs)));

        // 3. Create operator set 0
        IAllocationManagerTypes.CreateSetParams[] memory createOperatorSetParams =
            new IAllocationManagerTypes.CreateSetParams[](1);

        IStrategy[] memory opsetZero = new IStrategy[](1);
        opsetZero[0] = STRATEGY_WETH;

        createOperatorSetParams[0] = IAllocationManagerTypes.CreateSetParams({operatorSetId: 0, strategies: opsetZero});

        ALLOCATION_MANAGER.createOperatorSets(avs, createOperatorSetParams);
        console.log("Operator set created: ", ALLOCATION_MANAGER.getOperatorSetCount(avs));

        // Configure operator set 0 in the keyRegistrar
        OperatorSet memory operatorSet0 = OperatorSet({ avs: avs, id: 0 });

        console.log("Configuring operator set 0 for ECDSA...");
        KEY_REGISTRAR.configureOperatorSet(operatorSet0, IKeyRegistrarTypes.CurveType.BN254);

        string memory opset0Uri = "http://eigenkms-operator-set-0.com";
        RELEASE_MANAGER.publishMetadataURI(operatorSet0, opset0Uri);
        console.log("Operator set 0 metadata URI published");

        vm.stopBroadcast();
    }
}
