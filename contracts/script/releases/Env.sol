// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import "forge-std/Vm.sol";
import "zeus-templates/utils/ZEnvHelpers.sol";

import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";

import {EigenKMSRegistrar} from "../../src/EigenKMSRegistrar.sol";
import {EigenKMSCommitmentRegistry} from "../../src/EigenKMSCommitmentRegistry.sol";

library Env {
    using ZEnvHelpers for *;

    enum DeployedProxy { A }
    enum DeployedImpl { A }

    DeployedProxy internal constant proxy = DeployedProxy.A;
    DeployedImpl internal constant impl = DeployedImpl.A;

    /// Zeus environment variables
    function env() internal view returns (string memory) {
        return _string("ZEUS_ENV");
    }

    function envVersion() internal view returns (string memory) {
        return _string("ZEUS_ENV_VERSION");
    }

    function deployVersion() internal view returns (string memory) {
        return _string("ZEUS_DEPLOY_TO_VERSION");
    }

    /// EigenLayer core contracts (from deployment.json environment config)
    function allocationManager() internal view returns (address) {
        return _envAddress("AllocationManager");
    }

    function keyRegistrar() internal view returns (address) {
        return _envAddress("KeyRegistrar");
    }

    function permissionController() internal view returns (address) {
        return _envAddress("PermissionController");
    }

    /// Certificate verifiers (Base Sepolia)
    function ecdsaCertificateVerifier() internal view returns (address) {
        return _envAddress("ecdsaCertificateVerifier");
    }

    function bn254CertificateVerifier() internal view returns (address) {
        return _envAddress("bn254CertificateVerifier");
    }

    /// Governance
    function operatorOwner() internal view returns (address) {
        return _envAddress("operatorOwner");
    }

    /// Deployed contracts - proxies
    function eigenKMSRegistrar(DeployedProxy) internal view returns (EigenKMSRegistrar) {
        return EigenKMSRegistrar(_deployedProxy(type(EigenKMSRegistrar).name));
    }

    function eigenKMSCommitmentRegistry(DeployedProxy) internal view returns (EigenKMSCommitmentRegistry) {
        return EigenKMSCommitmentRegistry(_deployedProxy(type(EigenKMSCommitmentRegistry).name));
    }

    /// Deployed contracts - implementations
    function eigenKMSRegistrar(DeployedImpl) internal view returns (EigenKMSRegistrar) {
        return EigenKMSRegistrar(_deployedImpl(type(EigenKMSRegistrar).name));
    }

    function eigenKMSCommitmentRegistry(DeployedImpl) internal view returns (EigenKMSCommitmentRegistry) {
        return EigenKMSCommitmentRegistry(_deployedImpl(type(EigenKMSCommitmentRegistry).name));
    }

    /// ProxyAdmin
    function proxyAdmin() internal view returns (ProxyAdmin) {
        return ProxyAdmin(_deployedContract(type(ProxyAdmin).name));
    }

    /// Internal helpers
    function _deployedContract(string memory name) private view returns (address) {
        return ZEnvHelpers.state().deployedContract(name);
    }

    function _deployedProxy(string memory name) private view returns (address) {
        return ZEnvHelpers.state().deployedProxy(name);
    }

    function _deployedImpl(string memory name) private view returns (address) {
        return ZEnvHelpers.state().deployedImpl(name);
    }

    function _envAddress(string memory key) private view returns (address) {
        return ZEnvHelpers.state().envAddress(key);
    }

    function _envU256(string memory key) private view returns (uint256) {
        return ZEnvHelpers.state().envU256(key);
    }

    address internal constant VM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));
    Vm internal constant vm = Vm(VM_ADDRESS);

    function _string(string memory key) private view returns (string memory) {
        return vm.envString(key);
    }
}
