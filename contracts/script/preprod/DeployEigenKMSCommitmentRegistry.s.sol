// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {EigenKMSCommitmentRegistry} from "../../src/EigenKMSCommitmentRegistry.sol";

contract DeployEigenKMSCommitmentRegistry is Script {
    function setUp() public {}

    function run(
        address avs,
        uint32 operatorSetId,
        address ecdsaCertificateVerifier,
        address bn254CertificateVerifier,
        uint8 curveType
    ) public {
        // Load the private key from the environment variable
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY_DEPLOYER");
        address deployer = vm.addr(deployerPrivateKey);

        // 1. Deploy the EigenKMSCommitmentRegistry contract
        vm.startBroadcast(deployerPrivateKey);
        console.log("Deployer address:", deployer);
        console.log("AVS address:", avs);
        console.log("Operator Set ID:", operatorSetId);
        console.log("ECDSA Certificate Verifier:", ecdsaCertificateVerifier);
        console.log("BN254 Certificate Verifier:", bn254CertificateVerifier);
        console.log("Curve Type:", curveType, "(1=ECDSA, 2=BN254)");

        // Deploy ProxyAdmin
        ProxyAdmin proxyAdmin = new ProxyAdmin();
        console.log("ProxyAdmin deployed to:", address(proxyAdmin));

        // Deploy implementation
        EigenKMSCommitmentRegistry registryImpl = new EigenKMSCommitmentRegistry();
        console.log("EigenKMSCommitmentRegistry implementation deployed to:", address(registryImpl));

        // Deploy proxy with initialization
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(registryImpl),
            address(proxyAdmin),
            abi.encodeWithSelector(
                EigenKMSCommitmentRegistry.initialize.selector,
                deployer, // owner
                avs,
                operatorSetId,
                ecdsaCertificateVerifier,
                bn254CertificateVerifier,
                curveType
            )
        );
        console.log("EigenKMSCommitmentRegistry proxy deployed to:", address(proxy));

        // Transfer ProxyAdmin ownership to deployer (or a multisig in production)
        proxyAdmin.transferOwnership(deployer);
        console.log("ProxyAdmin ownership transferred to:", deployer);

        vm.stopBroadcast();

        // Log final deployment summary
        console.log("\n=== Deployment Summary ===");
        console.log("ProxyAdmin:", address(proxyAdmin));
        console.log("Implementation:", address(registryImpl));
        console.log("Proxy (use this address):", address(proxy));
        console.log("Owner:", deployer);
        console.log("========================\n");
    }
}
