# Immunefi Report Template

## Title

`[Severity] - [Vuln Type] in [contract/protocol name] allows [impact]`

Examples:
- "Critical - Reentrancy in VaultV2.withdraw() allows draining all deposited funds"
- "High - Access control bypass in GovernanceProxy.execute() allows unauthorized proposal execution"
- "Critical - Price oracle manipulation via flash loan allows undercollateralized borrowing"

---

## Report Body

### Vulnerability Details

**Protocol**: [Protocol name]
**Affected Contract(s)**:
- Address: `[0x...]`
- Chain: [Ethereum Mainnet / Polygon / Arbitrum / etc.]
- Contract name: [e.g., VaultV2.sol]
- Function(s): `[function name(s)]`

**Vulnerability Type**: [Reentrancy / Access Control / Logic Error / Oracle Manipulation / Flash Loan / etc.]

### Description

[Technical explanation of the vulnerability. Reference specific lines of code, state variables, and control flow. Explain why the bug exists and how the exploit works.]

```solidity
// Vulnerable code reference
function withdraw(uint256 amount) external {
    // [annotate the vulnerable logic]
    uint256 balance = balances[msg.sender];
    require(balance >= amount);
    (bool success, ) = msg.sender.call{value: amount}(""); // <-- vulnerability here
    balances[msg.sender] -= amount; // state update after external call
}
```

### Impact

**Classification**: [Critical / High / Medium / Low]

**Financial Impact**:
- TVL at risk: [$ amount or token amount]
- Attacker profit: [$ amount after costs]
- Capital required: [$ amount, or "flash loan available"]
- Gas cost: [ETH amount]
- Affected users/depositors: [number or "all depositors"]

**Impact Statement**:
[Specific description: "An attacker can drain all X tokens (currently $Y) from the Vault contract by..."]

### Risk Breakdown

- **Attack Complexity**: [Low -- single tx / Medium -- multi-step / High -- requires specific conditions]
- **Capital Required**: [None / Flash loan sufficient / Requires $X upfront capital]
- **Prerequisites**: [None / Specific token balance / Governance proposal / Time-locked condition]
- **Repeatability**: [One-time / Repeatable / Continuous]
- **Detection Risk**: [MEV bots may front-run / On-chain and visible / Difficult to detect]

### Proof of Concept

**Environment**:
- Framework: [Foundry / Hardhat]
- Fork: [Mainnet fork at block #XXXXXXX]
- RPC: [Provider]

**Setup & Execution**:
```bash
# Clone and run
git clone [repo with PoC]
cd [dir]
forge test --fork-url $RPC_URL --fork-block-number [block] --match-test testExploit -vvvv
```

**Exploit Code**:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract ExploitTest is Test {
    function setUp() public {
        // Fork setup, contract references
    }

    function testExploit() public {
        // Step 1: [description]
        // Step 2: [description]
        // Step 3: [description]

        // Verify impact
        assertGt(attackerBalanceAfter, attackerBalanceBefore);
    }
}
```

**Output** (expected):
```
[Paste test output showing successful exploit and balance changes]
```

### Recommended Fix

```solidity
// Fixed code
function withdraw(uint256 amount) external nonReentrant {
    uint256 balance = balances[msg.sender];
    require(balance >= amount);
    balances[msg.sender] -= amount; // state update before external call
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
}
```

[Explanation of why this fix resolves the vulnerability]

---

## Immunefi-Specific Notes

- Working exploit code is mandatory. Reports without PoC are auto-rejected.
- Always fork mainnet at a specific block for reproducibility.
- Include net profit calculation (revenue minus gas and capital costs).
- If flash loans are usable, demonstrate with a flash loan in your PoC.
- Specify all affected chains if the contract is deployed on multiple networks.
- Check if the bug exists in the implementation behind a proxy -- reference both proxy and implementation addresses.
