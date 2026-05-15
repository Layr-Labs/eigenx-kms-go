// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {EOADeployer} from "zeus-templates/templates/EOADeployer.sol";
import "../Env.sol";

import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {EigenKMSRegistrar} from "../../../src/EigenKMSRegistrar.sol";

contract RegisterContracts is EOADeployer {
    using Env for *;

    function _runAsEOA() internal override {
        deployContract({name: type(ProxyAdmin).name, deployedTo: address(Env.proxyAdmin())});
        deployImpl({name: type(EigenKMSRegistrar).name, deployedTo: address(Env.impl.eigenKMSRegistrar())});
        deployProxy({name: type(EigenKMSRegistrar).name, deployedTo: address(Env.proxy.eigenKMSRegistrar())});
    }

    function testScript() public virtual {
        runAsEOA();
        assertTrue(address(Env.proxyAdmin()) != address(0), "ProxyAdmin is zero");
        assertTrue(address(Env.proxy.eigenKMSRegistrar()) != address(0), "EigenKMSRegistrar proxy is zero");
        assertTrue(address(Env.impl.eigenKMSRegistrar()) != address(0), "EigenKMSRegistrar impl is zero");
    }
}
