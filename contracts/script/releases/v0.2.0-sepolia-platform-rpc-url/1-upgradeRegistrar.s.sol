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
 * @notice Upgrades the EigenKMSRegistrar implementation to add `AvsConfig.platformRpcUrl`
 *         + the `AvsConfigSet` event so KMS operators can discover the ecloud-platform
 *         gRPC endpoint on-chain, then sets the platformRpcUrl on the live proxy while
 *         preserving the existing operatorSetId.
 * @dev EOA phase: the operator EOA owns both the ProxyAdmin and the registrar (Ownable),
 *      so the impl deploy, the proxy upgrade, and setAvsConfig all run as that EOA.
 *
 *      The new platformRpcUrl is injected via the Zeus env var `platformRpcUrl`
 *      (Env.platformRpcUrl()). `operatorSetId` is read from the live proxy (post-upgrade,
 *      via the new signature) so the upgrade never clobbers it.
 *
 *      Non-atomic window: the proxy upgrade (tx 1) and setAvsConfig (tx 2) are separate
 *      transactions, so between them getAvsConfig().platformRpcUrl reads empty. Acceptable
 *      for sepolia-dev (no live operators); for mainnet, land both txs in one block (or use
 *      ProxyAdmin.upgradeAndCall once the registrar exposes a suitable initializer).
 */
/// @dev The v0.1.0 (pre-upgrade) AvsConfig had only `operatorSetId` — a STATIC return
/// tuple. The new `getAvsConfig()` returns a DYNAMIC tuple (it added a `string`), which is
/// ABI-encoded as an offset pointer. Decoding the old impl's static return with the new
/// signature mis-reads the offset and reverts/garbles, so any read of the config BEFORE the
/// upgrade must use this old-shaped signature.
interface IEigenKMSRegistrarV1 {
    struct AvsConfigV1 {
        uint32 operatorSetId;
    }

    function getAvsConfig() external view returns (AvsConfigV1 memory);
}

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
        // Read via the v0.1.0 (old-shaped) signature: before the upgrade the proxy still
        // points at the old impl, whose getAvsConfig() returns a STATIC (uint32) tuple —
        // decoding it with the new dynamic-tuple signature would revert (see note above).
        uint32 preOperatorSetId =
            IEigenKMSRegistrarV1(address(registrar)).getAvsConfig().operatorSetId;
        assertTrue(preOperatorSetId != 0, "sanity: proxy not initialised");

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
