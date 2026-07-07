# Zeus Onboarding for EigenX KMS Contracts

## Goal

Onboard existing Sepolia deployments onto Zeus so that future upgrades are managed via versioned release scripts with proper state tracking.

## Current State

- **EigenKMSRegistrar** deployed to Ethereum Sepolia (chain 11155111):
  - ProxyAdmin: `0x396453d3f233da7771f292a5aa9dcfb59c87241e`
  - Implementation: `0x7065a2442449450f072b106c26c037f2c13baead`
  - Proxy: `0xfe0c3c2db3b767f768f9000d48193f0ee0bfc07d`

- **EigenKMSCommitmentRegistry** deployed to Base Sepolia (chain 84532):
  - ProxyAdmin: `0x396453d3f233da7771f292a5aa9dcfb59c87241e`
  - Implementation: `0x7065a2442449450f072b106c26c037f2c13baead`
  - Proxy: `0xfe0c3c2db3b767f768f9000d48193f0ee0bfc07d`

- Both deployments are EOA-owned (no multisig governance yet)
- `.zeus` config file already exists pointing to `https://github.com/Layr-Labs/eigenx-kms-go-zeus-metadata` with `migrationDirectory: "contracts/script/releases"`

## Design

### Approach

Register-only onboarding: create init scripts that emit `ZeusDeploy` events for existing addresses without performing actual deployments. Existing state is captured in `deployment.json` files.

### File Structure

```
.zeus                                           # Existing - no changes needed
foundry.toml                                    # Updated with zeus remapping + no_match_path
package.json                                    # Add @layr-labs/zeus-cli
contracts/
├── lib/
│   └── zeus-templates/                         # New submodule
├── script/
│   ├── releases/
│   │   ├── Env.sol                             # Type-safe environment library
│   │   ├── v0.1.0-sepolia-init/
│   │   │   ├── upgrade.json
│   │   │   └── 1-registerContracts.s.sol
│   │   └── v0.1.0-base-sepolia-init/
│   │       ├── upgrade.json
│   │       └── 1-registerContracts.s.sol
│   ├── deploys/
│   │   ├── sepolia-dev/
│   │   │   └── deployment.json
│   │   └── base-sepolia-dev/
│   │       └── deployment.json
│   ├── preprod/                                # Existing - no changes
│   └── local/                                  # Existing - no changes
└── src/                                        # Existing - no changes
```

### deployment.json: sepolia-dev

```json
{
  "ENV": "sepolia-dev",
  "COMMIT": "",
  "VERSION": "0.1.0",
  "AllocationManager": "0x42583067658071247ec8CE0A516A58f682002d07",
  "KeyRegistrar": "0xA4dB30D08d8bbcA00D40600bee9F029984dB162a",
  "PermissionController": "0x44632dfBdCb6D3E21EF613B0ca8A6A0c618F5a37",
  "operatorOwner": "0x47c9806e7dc4e6fe9a0a2399831f32d06dae5730",
  "EigenKMSRegistrar_Impl": "0x7065a2442449450f072b106c26c037f2c13baead",
  "EigenKMSRegistrar_Proxy": "0xfe0c3c2db3b767f768f9000d48193f0ee0bfc07d",
  "ProxyAdmin": "0x396453d3f233da7771f292a5aa9dcfb59c87241e"
}
```

### deployment.json: base-sepolia-dev

```json
{
  "ENV": "base-sepolia-dev",
  "COMMIT": "",
  "VERSION": "0.1.0",
  "ecdsaCertificateVerifier": "0xb3Cd1A457dEa9A9A6F6406c6419B1c326670A96F",
  "bn254CertificateVerifier": "0xff58A373c18268F483C1F5cA03Cf885c0C43373a",
  "operatorOwner": "0x47c9806e7dc4e6fe9a0a2399831f32d06dae5730",
  "EigenKMSCommitmentRegistry_Impl": "0x7065a2442449450f072b106c26c037f2c13baead",
  "EigenKMSCommitmentRegistry_Proxy": "0xfe0c3c2db3b767f768f9000d48193f0ee0bfc07d",
  "ProxyAdmin": "0x396453d3f233da7771f292a5aa9dcfb59c87241e"
}
```

### upgrade.json: v0.1.0-sepolia-init

```json
{
  "name": "sepolia-init",
  "from": "0.0.0",
  "to": "0.1.0",
  "phases": [
    {
      "type": "eoa",
      "filename": "1-registerContracts.s.sol"
    }
  ]
}
```

### upgrade.json: v0.1.0-base-sepolia-init

```json
{
  "name": "base-sepolia-init",
  "from": "0.0.0",
  "to": "0.1.0",
  "phases": [
    {
      "type": "eoa",
      "filename": "1-registerContracts.s.sol"
    }
  ]
}
```

### Init Script Pattern (register-only)

Scripts extend `EOADeployer` and call `deployImpl`/`deployProxy`/`deployContract` with addresses read from the Zeus environment. No `vm.startBroadcast()` needed since nothing is actually deployed — Zeus just needs the events.

```solidity
contract RegisterContracts is EOADeployer {
    using Env for *;

    function _runAsEOA() internal override {
        // Register existing ProxyAdmin
        deployContract({name: type(ProxyAdmin).name, deployedTo: address(Env.proxyAdmin())});

        // Register existing implementation + proxy
        deployImpl({name: type(EigenKMSRegistrar).name, deployedTo: address(Env.impl.eigenKMSRegistrar())});
        deployProxy({name: type(EigenKMSRegistrar).name, deployedTo: address(Env.proxy.eigenKMSRegistrar())});
    }

    function testScript() public virtual {
        runAsEOA();
        // Validate registered addresses are non-zero
        assertTrue(address(Env.proxyAdmin()) != address(0));
        assertTrue(address(Env.proxy.eigenKMSRegistrar()) != address(0));
        assertTrue(address(Env.impl.eigenKMSRegistrar()) != address(0));
    }
}
```

### Env.sol Library

Provides type-safe accessors matching the reference project pattern:

- `Env.proxy.eigenKMSRegistrar()` -> `EigenKMSRegistrar`
- `Env.impl.eigenKMSRegistrar()` -> `EigenKMSRegistrar`
- `Env.proxy.eigenKMSCommitmentRegistry()` -> `EigenKMSCommitmentRegistry`
- `Env.impl.eigenKMSCommitmentRegistry()` -> `EigenKMSCommitmentRegistry`
- `Env.proxyAdmin()` -> `ProxyAdmin`
- `Env.allocationManager()` -> `IAllocationManager`
- `Env.keyRegistrar()` -> `IKeyRegistrar`
- `Env.permissionController()` -> `IPermissionController`
- `Env.operatorOwner()` -> `address`
- `Env.ecdsaCertificateVerifier()` -> `address`
- `Env.bn254CertificateVerifier()` -> `address`

Uses `ZEnvHelpers` from zeus-templates for underlying state management.

### foundry.toml Changes

Add to remappings:
```
"zeus-templates/=contracts/lib/zeus-templates/src/"
```

Add to config:
```toml
no_match_path = "contracts/script/releases/**/*.sol"
```

### package.json

```json
{
  "dependencies": {
    "@layr-labs/zeus-cli": "latest"
  }
}
```

### zeus-templates Installation

Install as a forge submodule:
```bash
cd contracts && forge install Layr-Labs/zeus-templates --no-commit
```

## Versioning Strategy

- `0.0.0` — pre-Zeus state (implicit, never deployed via Zeus)
- `0.1.0` — current deployed state captured by Zeus
- Future upgrades increment from `0.1.0`

## Testing

Each init script includes a `testScript()` function that validates registered addresses are non-zero. Zeus runs these as part of the migration flow.

## Out of Scope

- Mainnet deployments
- Multisig governance (currently EOA-owned)
- Full redeploy scripts (register-only for now)
