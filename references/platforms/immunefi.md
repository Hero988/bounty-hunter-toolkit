# Immunefi Platform Reference

## Platform Overview

Immunefi specializes in Web3, DeFi, and blockchain security. It hosts the highest individual bounty payouts in the industry, with some programs offering up to $10M+ for critical vulnerabilities. The PoC requirements and technical bar are correspondingly high.

---

## Severity Taxonomy

Immunefi uses its own classification system aligned with blockchain-specific impact.

### Smart Contract / Blockchain

| Severity | Impact | Typical Bounty |
|----------|--------|----------------|
| Critical | Direct theft of funds, permanent freezing of funds, protocol insolvency | $50,000 - $10,000,000+ |
| High | Theft of unclaimed yield/fees, permanent freezing of unclaimed yield, temporary freezing of funds (> 1 week) | $10,000 - $200,000 |
| Medium | Smart contract unable to operate (griefing), block stuffing, theft of gas | $5,000 - $50,000 |
| Low | Contract fails to deliver promised returns (but no loss), function-level issues | $1,000 - $10,000 |

### Web/App (if in scope)

| Severity | Impact | Typical Bounty |
|----------|--------|----------------|
| Critical | Direct impact on user funds via web interface, key/seed phrase exfiltration | $10,000 - $100,000 |
| High | Modify transaction parameters, address substitution in UI | $5,000 - $25,000 |
| Medium | XSS/CSRF affecting wallet interaction pages | $1,000 - $10,000 |
| Low | Information disclosure, non-fund-impacting bugs | $500 - $5,000 |

---

## PoC Requirements

Immunefi has strict Proof of Concept requirements. Reports without adequate PoC are rejected.

### Smart Contract PoC

```
Required:
1. Foundry or Hardhat test that demonstrates the exploit
2. Fork of mainnet state (or testnet if specified)
3. Step-by-step execution showing state changes
4. Before/after balance comparisons
5. Gas cost analysis for the attack

Example structure (Foundry):
forge test --fork-url $RPC_URL --match-test testExploit -vvvv
```

### Minimum PoC Components

| Component | Required | Description |
|-----------|----------|-------------|
| Exploit code | Yes | Working code that demonstrates the vulnerability |
| Fork test | Yes (smart contract) | Run against forked mainnet or testnet |
| State diff | Yes | Show balance/state changes before and after |
| Attack cost | Yes | Total cost to execute (gas, capital required) |
| Profit calculation | Yes (for fund theft) | Net profit for attacker after costs |
| Affected contracts | Yes | Exact addresses and chain IDs |
| Deployment block | Recommended | Block number for fork reproducibility |

### Web/App PoC

- Standard web vuln PoC (screenshots, video, HTTP requests)
- Must demonstrate impact on funds or wallet interaction
- Generic web vulns (XSS with no fund impact) are usually out of scope

---

## Blockchain-Specific Vulnerability Types

### Critical Severity

| Vuln Type | Description | Example |
|-----------|-------------|---------|
| Reentrancy | Recursive call drains funds before state update | DAO hack pattern |
| Flash loan attack | Manipulate oracle/price via flash loan | Price oracle manipulation |
| Access control | Unauthorized call to privileged function | Missing `onlyOwner` modifier |
| Logic error in math | Overflow/underflow, rounding error leading to fund theft | Compound cToken exchange rate bug |
| Cross-chain replay | Transaction valid on multiple chains | Signature reuse across chains |
| Governance takeover | Manipulate voting to pass malicious proposal | Flash loan + governance vote |
| Oracle manipulation | Corrupt price feed to exploit dependent contracts | TWAP manipulation |
| Proxy upgrade | Unauthorized upgrade of proxy implementation | Storage collision + upgrade |

### High Severity

| Vuln Type | Description |
|-----------|-------------|
| Yield theft | Steal unclaimed rewards/fees |
| Temporary DoS | Freeze contract for extended period (> 1 week) |
| Front-running | Extract value via transaction ordering |
| Sandwich attack (novel) | Only if exploiting a protocol-specific flaw, not generic MEV |
| Improper liquidation | Liquidation logic allows unfair liquidation or prevents valid liquidation |

### Medium Severity

| Vuln Type | Description |
|-----------|-------------|
| Griefing | Make contract unusable without direct profit |
| Gas manipulation | Force excessive gas consumption |
| Dust attacks | Small-value attacks that disrupt accounting |
| Event manipulation | Emit false events that mislead off-chain systems |

### Usually Out of Scope

- Generic front-running / MEV (considered known risk)
- Best practice issues without demonstrated impact
- Centralization risks (admin can rug -- this is a design choice, not a bug)
- Known issues listed in audits
- Bugs in forked code that are already public
- Theoretical attacks requiring > $100M capital

---

## Report Structure

### Required Sections

1. **Vulnerability Details**: Technical description with contract references
2. **Impact**: Specific financial impact with calculations
3. **Risk Breakdown**: Attack complexity, capital required, prerequisites
4. **Proof of Concept**: Working exploit code (Foundry/Hardhat test)
5. **Affected Contracts**: Addresses, chains, and deployment details
6. **Recommended Fix**: Suggested mitigation

### Impact Calculation Template

```
Attack scenario:
- Capital required: [X ETH / X USDC]
- Flash loan available: [Yes/No]
- Gas cost: [X ETH]
- Expected profit: [X ETH / X USDC]
- Net profit: [Expected - Costs]
- TVL at risk: [Total value locked in affected contracts]
- Affected users: [Number/percentage]
```

---

## Triage Process

### Flow

```
Submitted --> Immunefi Review (48-72 hrs) --> Project Review --> Bounty / Rejected
```

### Key Characteristics

- **PoC-first**: Without working PoC, report is auto-rejected
- **Project communication**: Immunefi mediates between hunter and project team
- **Fix verification**: Hunter may be asked to verify the fix
- **NDA common**: Many programs require NDA before disclosure
- **Payment**: Crypto (USDC, ETH) or fiat via wire transfer. Large bounties may be paid in project tokens (with vesting).

### Response Times

- Immunefi initial review: 48-72 hours
- Project review: 1-2 weeks (varies significantly)
- Bounty payment: 1-4 weeks after acceptance
- For critical fund-at-risk bugs: expedited review (same day possible)

---

## Practical Tips

- **Read the audit reports**: Most Immunefi programs have prior audits listed. Read them to understand known issues and the codebase.
- **Check the code diff**: If the protocol recently upgraded, diff the new implementation against the old one. New code = new bugs.
- **Fork mainnet for testing**: Always test against actual state. Bugs that work on a clean deployment but not mainnet are not valid.
- **Capital requirements matter**: A bug requiring $100M in capital with no flash loan availability is lower severity than one exploitable with a $1000 flash loan.
- **Monitor governance proposals**: Pending governance changes can introduce vulnerabilities. Test proposed changes before they are executed.
- **Time-sensitive bugs**: If funds are actively at risk, use Immunefi's emergency contact. Do not wait for normal triage.
- **Competition is technical**: Immunefi hunters are typically smart contract auditors. Surface-level bugs are already found. Focus on complex logic, cross-contract interactions, and edge cases.
- **Exclusions are strict**: If the program says "centralization risks are out of scope," do not report admin key risks regardless of impact.
