# Zeus Onboarding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Onboard existing Sepolia deployments onto Zeus so future contract upgrades use versioned release scripts with state tracking.

**Architecture:** Install zeus-templates as a forge submodule, create deployment.json files capturing existing addresses, build an Env.sol library for type-safe contract access, and write register-only init scripts that emit ZeusDeploy events without actual deployments.

**Tech Stack:** Foundry (forge), zeus-templates, Solidity 0.8.27, Zeus CLI

---

## File Map

| Action | Path | Purpose |
|--------|------|---------|
| Modify | `foundry.toml` | Add zeus-templates remapping + no_match_path |
| Modify | `package.json` | Add @layr-labs/zeus-cli dependency |
| Install | `contracts/lib/zeus-templates/` | Forge submodule |
| Create | `contracts/script/deploys/sepolia-dev/deployment.json` | Eth Sepolia state |
| Create | `contracts/script/deploys/base-sepolia-dev/deployment.json` | Base Sepolia state |
| Create | `contracts/script/releases/Env.sol` | Type-safe env library |
| Create | `contracts/script/releases/v0.1.0-sepolia-init/upgrade.json` | Migration metadata |
| Create | `contracts/script/releases/v0.1.0-sepolia-init/1-registerContracts.s.sol` | Register script |
| Create | `contracts/script/releases/v0.1.0-base-sepolia-init/upgrade.json` | Migration metadata |
| Create | `contracts/script/releases/v0.1.0-base-sepolia-init/1-registerContracts.s.sol` | Register script |

---

### Task 1: Install zeus-templates submodule

**Files:**
- Install: `contracts/lib/zeus-templates/` (forge submodule)

- [ ] **Step 1: Install zeus-templates via forge**

```bash
forge install Layr-Labs/zeus-templates --no-commit --root contracts
```

- [ ] **Step 2: Verify installation**

```bash
ls contracts/lib/zeus-templates/src/templates/EOADeployer.sol
```

Expected: file exists

- [ ] **Step 3: Commit**

```bash
git add contracts/lib/zeus-templates .gitmodules
git commit -m "chore: add zeus-templates submodule"
```

---

### Task 2: Update foundry.toml

**Files:**
- Modify: `foundry.toml`

- [ ] **Step 1: Add zeus-templates remapping**

Add `"zeus-templates/=contracts/lib/zeus-templates/src/"` to the remappings array in `foundry.toml`. The full remappings should be:

```toml
remappings = [
    "forge-std/=contracts/lib/forge-std/src/",
    "@eigenlayer-middleware/=contracts/lib/eigenlayer-middleware/",
    "@eigenlayer-contracts/=contracts/lib/eigenlayer-middleware/lib/eigenlayer-contracts/",
    "@openzeppelin/=contracts/lib/eigenlayer-middleware/lib/openzeppelin-contracts/",
    "@openzeppelin-upgrades/=contracts/lib/eigenlayer-middleware/lib/openzeppelin-contracts-upgradeable/",
    "zeus-templates/=contracts/lib/zeus-templates/src/"
]
```

- [ ] **Step 2: Add no_match_path for releases**

Add this line after the `optimizer_runs` setting (before the `ignored_warnings_from` block):

```toml
no_match_path = "contracts/script/releases/**/*.sol"
```

- [ ] **Step 3: Verify forge build still works**

```bash
forge build
```

Expected: successful compilation (release scripts are excluded from compilation)

- [ ] **Step 4: Commit**

```bash
git add foundry.toml
git commit -m "chore: add zeus-templates remapping and exclude releases from build"
```

---

### Task 3: Update package.json

**Files:**
- Modify: `package.json`

- [ ] **Step 1: Write package.json with zeus-cli dependency**

```json
{
  "dependencies": {
    "@layr-labs/zeus-cli": "latest"
  }
}
```

- [ ] **Step 2: Install dependencies**

```bash
npm install
```

- [ ] **Step 3: Commit**

```bash
git add package.json package-lock.json
git commit -m "chore: add @layr-labs/zeus-cli dependency"
```

---

### Task 4: Create deployment.json files

**Files:**
- Create: `contracts/script/deploys/sepolia-dev/deployment.json`
- Create: `contracts/script/deploys/base-sepolia-dev/deployment.json`

- [ ] **Step 1: Create sepolia-dev deployment.json**

Create directory `contracts/script/deploys/sepolia-dev/` and write:

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

- [ ] **Step 2: Create base-sepolia-dev deployment.json**

Create directory `contracts/script/deploys/base-sepolia-dev/` and write:

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

- [ ] **Step 3: Commit**

```bash
git add contracts/script/deploys/
git commit -m "chore: add deployment.json files for existing sepolia deployments"
```

---

### Task 5: Create Env.sol library

**Files:**
- Create: `contracts/script/releases/Env.sol`

- [ ] **Step 1: Write Env.sol**

Create directory `contracts/script/releases/` and write:

```solidity
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
```

- [ ] **Step 2: Commit**

```bash
git add contracts/script/releases/Env.sol
git commit -m "feat: add Env.sol library for Zeus type-safe environment access"
```

---

### Task 6: Create v0.1.0-sepolia-init release

**Files:**
- Create: `contracts/script/releases/v0.1.0-sepolia-init/upgrade.json`
- Create: `contracts/script/releases/v0.1.0-sepolia-init/1-registerContracts.s.sol`

- [ ] **Step 1: Create upgrade.json**

Create directory `contracts/script/releases/v0.1.0-sepolia-init/` and write:

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

- [ ] **Step 2: Create 1-registerContracts.s.sol**

```solidity
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
```

- [ ] **Step 3: Commit**

```bash
git add contracts/script/releases/v0.1.0-sepolia-init/
git commit -m "feat: add v0.1.0-sepolia-init Zeus release (register existing EigenKMSRegistrar)"
```

---

### Task 7: Create v0.1.0-base-sepolia-init release

**Files:**
- Create: `contracts/script/releases/v0.1.0-base-sepolia-init/upgrade.json`
- Create: `contracts/script/releases/v0.1.0-base-sepolia-init/1-registerContracts.s.sol`

- [ ] **Step 1: Create upgrade.json**

Create directory `contracts/script/releases/v0.1.0-base-sepolia-init/` and write:

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

- [ ] **Step 2: Create 1-registerContracts.s.sol**

```solidity
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
```

- [ ] **Step 3: Commit**

```bash
git add contracts/script/releases/v0.1.0-base-sepolia-init/
git commit -m "feat: add v0.1.0-base-sepolia-init Zeus release (register existing EigenKMSCommitmentRegistry)"
```

---

### Task 8: Verify compilation of release scripts

**Files:**
- None (verification only)

- [ ] **Step 1: Compile release scripts explicitly**

Release scripts are excluded from `forge build` via `no_match_path`, but we should verify they compile when targeted directly:

```bash
forge build --match-path "contracts/script/releases/v0.1.0-sepolia-init/1-registerContracts.s.sol"
```

Expected: successful compilation

- [ ] **Step 2: Compile base-sepolia init script**

```bash
forge build --match-path "contracts/script/releases/v0.1.0-base-sepolia-init/1-registerContracts.s.sol"
```

Expected: successful compilation

- [ ] **Step 3: Verify normal build still excludes releases**

```bash
forge build
```

Expected: successful compilation (release scripts not included in default compilation)
