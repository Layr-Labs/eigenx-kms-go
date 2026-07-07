// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {EOADeployer} from "zeus-templates/templates/EOADeployer.sol";
import "../Env.sol";

import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";

import {IAllocationManager} from "@eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import {IKeyRegistrar} from "@eigenlayer-contracts/src/contracts/interfaces/IKeyRegistrar.sol";
import {IPermissionController} from "@eigenlayer-contracts/src/contracts/interfaces/IPermissionController.sol";
import {EigenKMSRegistrar} from "../../../src/EigenKMSRegistrar.sol";
import {IEigenKMSRegistrarTypes} from "../../../src/interfaces/IEigenKMSRegistrar.sol";

/**
 * @title UpgradeRegistrar (v0.2.0, sepolia-dev)
 * @notice Upgrades the EigenKMSRegistrar implementation to the version built in PR #120,
 *         which adds `AvsConfig.platformRpcUrl` + the `AvsConfigSet` event so KMS operators
 *         can discover the ecloud-platform gRPC endpoint on-chain, then sets the
 *         platformRpcUrl on the live proxy while preserving the existing operatorSetId.
 * @dev EOA phase: the operator EOA owns both the ProxyAdmin and the registrar (Ownable),
 *      so the impl deploy, the proxy upgrade, and setAvsConfig all run as that EOA.
 *
 *      The new platformRpcUrl is injected via the Zeus env var `platformRpcUrl`
 *      (Env.platformRpcUrl()). `operatorSetId` is read from the live proxy so the upgrade
 *      never clobbers it.
 */
contract UpgradeRegistrar is EOADeployer {
    using Env for *;

    function _runAsEOA() internal override {
        ProxyAdmin proxyAdmin = Env.proxyAdmin();
        EigenKMSRegistrar registrar = Env.proxy.eigenKMSRegistrar();

        // Fail fast (at dry-run time) if the platform endpoint wasn't injected — an empty
        // platformRpcUrl would silently leave operator discovery broken.
        require(bytes(Env.platformRpcUrl()).length > 0, "platformRpcUrl env var not set");

        // On-chain transactions run inside the broadcast segment: deploy the new impl,
        // repoint the proxy, and set the platform URL. Zeus state recording (deployImpl)
        // is done AFTER, outside the broadcast, per the zeus-templates convention.
        vm.startBroadcast();

        // 1. Deploy the new EigenKMSRegistrar implementation with the same immutables
        //    used at init (constructor args wired to the environment's core contracts).
        EigenKMSRegistrar newImpl = new EigenKMSRegistrar(
            IAllocationManager(Env.allocationManager()),
            IKeyRegistrar(Env.keyRegistrar()),
            IPermissionController(Env.permissionController())
        );

        // 2. Repoint the proxy at the new implementation via the ProxyAdmin (owned by the EOA).
        proxyAdmin.upgrade(ITransparentUpgradeableProxy(address(registrar)), address(newImpl));

        // 3. Populate platformRpcUrl on the live proxy, preserving the existing operatorSetId.
        IEigenKMSRegistrarTypes.AvsConfig memory current = registrar.getAvsConfig();
        registrar.setAvsConfig(
            IEigenKMSRegistrarTypes.AvsConfig({
                operatorSetId: current.operatorSetId,
                platformRpcUrl: Env.platformRpcUrl()
            })
        );

        vm.stopBroadcast();

        // Record the new implementation in Zeus state (outside the broadcast segment).
        deployImpl({name: type(EigenKMSRegistrar).name, deployedTo: address(newImpl)});
    }

    function testScript() public virtual {
        EigenKMSRegistrar registrar = Env.proxy.eigenKMSRegistrar();
        ProxyAdmin proxyAdmin = Env.proxyAdmin();

        // Capture the pre-upgrade operatorSetId so we can prove the upgrade preserves it.
        uint32 preOperatorSetId = registrar.getAvsConfig().operatorSetId;

        runAsEOA();

        // Proxy now points at the newly deployed implementation.
        assertEq(
            proxyAdmin.getProxyImplementation(ITransparentUpgradeableProxy(address(registrar))),
            address(Env.impl.eigenKMSRegistrar()),
            "proxy not upgraded to new impl"
        );

        // platformRpcUrl is set to the injected value; operatorSetId is preserved (non-clobbered).
        IEigenKMSRegistrarTypes.AvsConfig memory cfg = registrar.getAvsConfig();
        assertEq(cfg.platformRpcUrl, Env.platformRpcUrl(), "platformRpcUrl not set");
        assertEq(cfg.operatorSetId, preOperatorSetId, "operatorSetId must not change");
    }
}
