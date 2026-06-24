// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {EOADeployer} from "zeus-templates/templates/EOADeployer.sol";
import "../Env.sol";

import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {EigenKMSCommitmentRegistry} from "../../../src/EigenKMSCommitmentRegistry.sol";

contract RegisterContracts is EOADeployer {
    using Env for *;

    function _runAsEOA() internal override {
        deployContract({name: type(ProxyAdmin).name, deployedTo: address(Env.proxyAdmin())});
        deployImpl({name: type(EigenKMSCommitmentRegistry).name, deployedTo: address(Env.impl.eigenKMSCommitmentRegistry())});
        deployProxy({name: type(EigenKMSCommitmentRegistry).name, deployedTo: address(Env.proxy.eigenKMSCommitmentRegistry())});
    }

    function testScript() public virtual {
        runAsEOA();
        assertTrue(address(Env.proxyAdmin()) != address(0), "ProxyAdmin is zero");
        assertTrue(address(Env.proxy.eigenKMSCommitmentRegistry()) != address(0), "EigenKMSCommitmentRegistry proxy is zero");
        assertTrue(address(Env.impl.eigenKMSCommitmentRegistry()) != address(0), "EigenKMSCommitmentRegistry impl is zero");
    }
}
