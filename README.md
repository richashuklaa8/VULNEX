# VULNEX: MetaMask + Ethereum Sepolia

VULNEX audits a Solidity contract and records the audit on **Ethereum Sepolia** through **MetaMask**. Anyone can then check the report against that on-chain record.

```text
Scan contract → Findings → Audit report → SHA-256 report hash
→ Connect MetaMask → Attest → MetaMask confirmation → Sepolia transaction
→ AuditRegistry stores the hashes → real tx hash + block number in the UI
→ Verify the report against Sepolia
```

Only the simulated attestation was replaced. Scanning, findings, fixes, compare, explorer, report generation, SHA-256 hashing and the design are the same as before.

---

## 1. Files changed

| File | What changed |
|---|---|
| `index.html` | The simulated attestation (`attest()`, `renderSide()`, `drawQR()`) is replaced with the real MetaMask flow, and verification (`runVerify()`, `renderVerify()`) now reads Sepolia. The changes also add a wallet button in the header, routes for verifying by report hash, and AI fixes through the local server. Everything else is untouched. |

## 2. Files created

| File | Purpose |
|---|---|
| `src/blockchain.js` | MetaMask + Sepolia module (ethers v6): connect, network check/switch, `attest`, `verify`, optional deploy, friendly errors |
| `server/index.js` | Local server on `http://localhost:5173`. Serves the app, reads `.env`, forwards read-only Sepolia calls, and forwards AI prompts to OpenRouter |
| `contracts/AuditRegistry.sol` | The registry contract (exactly as specified) |
| `contracts/AuditRegistry.json` | Its ABI + bytecode (solc 0.8.24, optimizer on, EVM paris) |
| `samples/VulnerableBank.sol` | Demo contract |
| `package.json`, `package-lock.json` | Dependencies and `npm start` |
| `.env`, `.env.example` | Settings (see section 5) |
| `.gitignore` | Keeps `.env` and `node_modules` out of git |

## 3. npm packages

- `ethers` 6.17.0: MetaMask (BrowserProvider) and contract calls
- `qrious` 4.0.2: QR code on the certificate, served locally so it works offline

No Hardhat, no build step, no framework.

## 4. Run it locally

Requires **Node.js 18.17 or newer** (Node 20 or 22 LTS recommended).

```bash
cd vulnex
npm install
npm start
```

Open **http://localhost:5173** in the browser where MetaMask is installed. Stop with `Ctrl+C`.

> Open it through `npm start`, not by double-clicking `index.html`. MetaMask does not work on `file://` pages.

## 5. Environment variables (`.env`)

| Variable | Required | What it is |
|---|---|---|
| `AUDIT_REGISTRY_ADDRESS` | Yes, after you deploy | Public address of your deployed AuditRegistry contract on Sepolia |
| `OPENROUTER_API_KEY` | For AI fixes | Your OpenRouter key. Stays on the server; never sent to the browser |
| `OPENROUTER_MODEL` | No | Default `anthropic/claude-sonnet-5.5` |
| `SEPOLIA_RPC_URL` | No | RPC used for read-only checks when MetaMask isn't on Sepolia. Default: `https://ethereum-sepolia-rpc.publicnode.com` |
| `PORT` | No | Default `5173` |

**Never** put a MetaMask private key or seed phrase in `.env` or anywhere in this project. Nothing here asks for one. MetaMask signs every transaction itself after you confirm it.

`VITE_AUDIT_REGISTRY_ADDRESS` is also accepted, if you prefer that name.

## 6. Where to paste the contract address

In `.env`:

```env
AUDIT_REGISTRY_ADDRESS=0xYourDeployedAuditRegistryAddress
```

Save the file and **reload the page**; no restart needed. The Report page shows it under **Registry … from .env**.

> Paste the **contract** address, not your wallet address. If you paste a wallet address, the app says *"No AuditRegistry contract at this address on Sepolia."*

### Deploying AuditRegistry (one time)

**Option A: from VULNEX (easiest).** Leave `AUDIT_REGISTRY_ADDRESS` empty, then:

1. Go to the Report page.
2. Click **Deploy AuditRegistry to Sepolia** and confirm in MetaMask.
3. The address is saved in this browser right away, so you can attest immediately.
4. The page shows the exact `.env` line to paste so it works in every browser.

**Option B: Remix.**

1. Open https://remix.ethereum.org and create `AuditRegistry.sol` with the contents of `contracts/AuditRegistry.sol`.
2. On the **Solidity compiler** tab, choose 0.8.20 or newer and click **Compile**.
3. On the **Deploy & run** tab, set Environment to **Injected Provider – MetaMask**, with MetaMask on Sepolia.
4. Click **Deploy** and confirm in MetaMask.
5. Copy the address from **Deployed Contracts** into `.env`.

## 7. Connect MetaMask

1. Install MetaMask from https://metamask.io/download/ and create or import a wallet.
2. Open http://localhost:5173 and click **Connect wallet** (top right), or **Connect MetaMask** on the Report page.
3. Approve the connection in MetaMask. The header shows `Sepolia · 0x1234…ABCD`.

## 8. Switch to Sepolia

If MetaMask is on another network, the header shows **Switch to Sepolia** and the Report page says *"Please switch MetaMask to Sepolia."* Click **Switch to Sepolia** and approve the request in MetaMask. The app never switches networks without your confirmation.

You can also pick Sepolia in MetaMask's network menu. If it isn't listed, turn on **Show test networks** there.

## 9. Get Sepolia test ETH (free)

Each attestation uses about 135,000 gas, and deploying the registry about 183,000 gas. A single faucet claim covers many attestations. These faucets need no mainnet ETH:

- Google Cloud faucet (Google account): https://cloud.google.com/application/web3/faucet/ethereum/sepolia
- PoW faucet (no account, mines in your browser): https://sepolia-faucet.pk910.de/
- QuickNode faucet: https://faucet.quicknode.com/ethereum/sepolia

Paste your **wallet** address into the faucet.

## 10. Test Attest

1. **Audit** → **Apply all 6 suggested fixes** → **Re-scan as V2**.
2. **Report** → check that Network, Wallet and Registry look right.
3. Click **Attest on Sepolia**. MetaMask opens; check the request and click **Confirm**.
4. Watch the steps. *Wait for Sepolia to confirm* takes about 10–30 seconds and links to Etherscan while pending.
5. The panel shows **✓ Attested** with the real transaction hash, block number, and **View on Etherscan**. The certificate's QR code opens the transaction on Sepolia Etherscan.

## 11. Test Verify

1. On the Report page, click **Verify on Sepolia**, or go to **Verify** and enter the Audit ID.
2. You should see **✓ VERIFIED**: *"This audit report matches the blockchain attestation."* The page also shows the auditor wallet, timestamp, contract hash and block number, all read from the contract.
3. **Tamper test:** click **Rewrite the verdict** → **Verify this copy**. You should see **✗ VERIFICATION FAILED**: *"The current report does not match the blockchain attestation."*
4. **From another browser or device:** enter the **report hash** (`0x…`) instead of the Audit ID. You get **✓ ATTESTATION FOUND**. Paste the report JSON (Report → Copy report JSON) to fully verify it.

`TSX-DEMO01` is the old built-in example. It is checked offline and labelled *not on Sepolia*.

## 12. Common errors and fixes

| Message | Cause | Fix |
|---|---|---|
| MetaMask is not installed. | No MetaMask in this browser | Install it, then reload |
| Wallet offline | Page opened as a file, or server not running | Run `npm start` and open http://localhost:5173 |
| Connection request rejected. | You clicked Cancel in MetaMask | Click Connect again and approve |
| MetaMask is waiting for you. | A MetaMask request is already open | Open the MetaMask extension and finish it |
| Please switch MetaMask to Sepolia. | Wrong network | Click **Switch to Sepolia** and approve |
| No AuditRegistry contract is configured. | `AUDIT_REGISTRY_ADDRESS` is empty | Deploy (section 6), then paste the address and reload |
| The AuditRegistry address is not valid. | Typo in `.env` | It must be `0x` + 40 hex characters |
| No AuditRegistry contract at this address on Sepolia. | Wallet address or wrong-network address pasted | Use the deployed **contract** address |
| Not enough Sepolia ETH. | Wallet has no test ETH | Use a faucet (section 9) |
| Transaction rejected. | You clicked Reject in MetaMask | Nothing was written; click Attest again |
| Transaction still pending. | Sepolia was slow or the connection dropped | Click **Check status**, or open the Etherscan link |
| Transaction reverted. | The contract refused the call | Check the registry address points to AuditRegistry |
| Could not reach Sepolia. | Network or RPC problem | Check your internet. Optionally set `SEPOLIA_RPC_URL` (e.g. an Infura or Alchemy Sepolia URL) |
| Port 5173 is already in use. | Another app uses the port | Close it, or add `PORT=5174` to `.env` |
| OpenRouter rejected the API key. | Wrong or revoked key | Fix `OPENROUTER_API_KEY` and reload |
| Your OpenRouter account is out of credits. | No OpenRouter balance | Add credits at openrouter.ai |

---

### Security notes

- MetaMask signs every transaction after you confirm it. The app never sees keys or seed phrases.
- The OpenRouter key is read only by the local server. `/config.js` tells the browser whether AI is on, never the key.
- The server listens on `127.0.0.1` only. It rejects requests from other websites and serves only the app's own files, never `.env`.
- Only hashes go on-chain, never the report or the source code.
- A verified attestation proves the record is unaltered. It does not prove the contract is secure.
- The contract follows the spec exactly: `attest()` can be called again for the same report hash and replaces the stored record. If you have not deployed yet and want first-write-wins, add `require(attestations[reportHash].timestamp == 0, "Already attested");` as the first line of `attest()`. The ABI stays the same, so the app keeps working.

### Contract interface used by the app

```solidity
function attest(bytes32 reportHash, bytes32 contractHash) external;
function verify(bytes32 reportHash) external view returns (bytes32, bytes32, address, uint256, uint256);
event Attested(bytes32 indexed reportHash, bytes32 indexed contractHash, address indexed auditor);
```

`reportHash` is SHA-256 of the canonical report JSON. `contractHash` is SHA-256 of the contract source. Both are the hashes VULNEX already computed, passed as `bytes32`.
