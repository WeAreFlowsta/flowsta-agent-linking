# Flowsta Agent Linking

Reusable Holochain zome pair for cross-conductor agent identity linking. Allows users to prove that two agent keys (on different conductors/DHTs) belong to the same person via pairwise Ed25519 signatures.

Designed for third-party Holochain apps that authenticate users through [Flowsta Vault](https://flowsta.com/vault) - but the zome is fully generic and can be used for any pairwise agent linking scenario.

## How It Works

1. User has **Agent Key A** (Flowsta Vault, on their device)
2. User has **Agent Key X** (your app, on your DHT)
3. Your app asks Flowsta Vault (via IPC) to sign the sorted key pair `[A, X]`
4. Your app's conductor signs the same payload
5. Both signatures are stored in an `IsSamePersonEntry` on **your DHT**
6. Anyone on your DHT can verify: "Agent X is the same person as Flowsta identity A"

No shared DNA, no API dependency, pure Ed25519 cryptography.

## Quick Start

### 1. Add the crates to your DNA

The crates are consumed as a git dependency pinned to a release tag. They pin
`hdi = 0.8.0`-style exact versions internally: your DNA's `hdi` / `hdk` must be
on the same Holochain line (this tag: Holochain 0.6, `hdi =0.7.0`, `hdk =0.6.0`),
or the build fails with trait-resolution errors rather than a clear message.

```toml
# In your integrity zome's Cargo.toml
[dependencies]
flowsta-agent-linking-integrity = { git = "https://github.com/WeAreFlowsta/flowsta-agent-linking", tag = "v0.3.0" }

# In your coordinator zome's Cargo.toml
[dependencies]
flowsta-agent-linking-coordinator = { git = "https://github.com/WeAreFlowsta/flowsta-agent-linking", tag = "v0.3.0" }
```

### 2. Add the zomes to your DNA manifest

```yaml
# dna.yaml
coordinator:
  zomes:
    - name: agent_linking
      bundled: "path/to/flowsta_agent_linking_coordinator.wasm"
integrity:
  zomes:
    - name: agent_linking_integrity
      bundled: "path/to/flowsta_agent_linking_integrity.wasm"
```

### 3. Build with RUSTFLAGS

```bash
RUSTFLAGS='--cfg getrandom_backend="custom"' cargo build \
  --release --target wasm32-unknown-unknown
```

### 4. Link identity from your frontend

```typescript
import { linkFlowstaIdentity } from '@flowsta/holochain';
import { decodeHashFromBase64 } from '@holochain/client';

// Get signed payload from Flowsta Vault (shows approval dialog)
const result = await linkFlowstaIdentity({
  appName: 'YourApp',
  localAgentPubKey: myAgentKey, // uhCAk... from your conductor
});

// Call your zome with the signed payload
await appWs.callZome({
  role_name: 'your_app',
  zome_name: 'agent_linking',
  fn_name: 'create_external_link',
  payload: {
    external_agent: decodeHashFromBase64(result.payload.vaultAgentPubKey),
    // The Vault's signature arrives base64-encoded; the zome wants raw bytes.
    external_signature: Uint8Array.from(atob(result.payload.vaultSignature), (c) => c.charCodeAt(0)),
  },
});
```

### 5. Query linked identity

```typescript
const linkedAgents = await appWs.callZome({
  role_name: 'your_app',
  zome_name: 'agent_linking',
  fn_name: 'get_linked_agents',
  payload: someAgentPubKey,
});
// Returns: [vaultAgentPubKey] - Flowsta identity verified on-DHT
```

## Zome Functions

| Function | Input | Output | Purpose |
|---|---|---|---|
| `create_external_link` | `{ external_agent, external_signature }` | `ActionHash` | Link local agent to external (Vault) agent |
| `get_linked_agents` | `AgentPubKey` | `Vec<AgentPubKey>` | Query all linked agents (non-deleted) |
| `are_agents_linked` | `{ agent_a, agent_b }` | `bool` | Check if two agents are linked |
| `revoke_link` | `ActionHash` | `ActionHash` | Delete the pairwise entry |

**One agent, one external identity.** `create_external_link` refuses when the calling agent already holds a live link to a *different* external agent: a second attestation would publish a claim that two people are one. Linking the same external agent again is allowed (reinstall, restore). To move an agent to another identity on purpose, `revoke_link` the old entry first. Flowsta Vault applies the same rule on its side before showing any dialog; its identity switcher is where apps meet this case.

## What the DHT guarantees, and what it does not

Enforced by the integrity zome on every peer (a modified coordinator cannot get
around these):

- An `IsSamePersonEntry` carries two different keys in canonical order, its
  author is one of them, and both raw Ed25519 signatures verify over the sorted
  78-byte key pair. No forged attestation.
- Only one of the two agents named in an entry can delete (revoke) it.
- A lookup link (`AgentToIsSamePerson`) must start from one of the two agents
  named in the entry it points at, and be written by one of them. A lookup can
  therefore never answer with an attestation that did not name the queried agent.

Enforced by the coordinator only (an app-side rule, not a DHT guarantee):

- **One agent, one external identity.** `create_external_link` refuses when the
  calling agent already holds a live link to a *different* external agent. The
  check reads the DHT, so it cannot live in validation; Flowsta Vault applies
  the same rule on its side before showing any dialog.

## Entry Type

```rust
pub struct IsSamePersonEntry {
    pub agent_a: AgentPubKey,       // Lexicographically smaller key
    pub signature_a: Signature,     // Raw Ed25519 sig over sorted pair
    pub agent_b: AgentPubKey,       // Lexicographically larger key
    pub signature_b: Signature,     // Raw Ed25519 sig over sorted pair
    pub created_at: i64,            // Unix timestamp
}
```

Both signatures are raw Ed25519 over the 78-byte sorted key pair (39 bytes per key, sorted lexicographically, concatenated). No MessagePack encoding.

## Signature Format

This crate uses `sign_raw`/`verify_signature_raw` (not `sign`/`verify_signature`). This is critical for cross-conductor compatibility:

- Holochain's `sign()`/`verify_signature()` MessagePack-encode the payload before signing
- External signers (Flowsta Vault, ed25519-dalek, libsodium, tweetnacl) sign raw bytes
- Using `sign_raw`/`verify_signature_raw` ensures both sides sign the same representation

## Holochain Version

Tag `v0.3.0` (integrity 0.2.0, coordinator 0.3.0) targets Holochain 0.6 (`hdi =0.7.0`, `hdk =0.6.0`). A Holochain 0.7 line will be a separate tag: 0.7 recompiles every zome to a new DNA hash.

## Versions

| Tag | Integrity | Coordinator | Change |
|---|---|---|---|
| v0.3.0 | 0.2.0 | 0.3.0 | Validation: only a participant may revoke an entry or write its lookup links; lookups answer only for agents named in the entry. New DNA hash for apps that embed the integrity zome. |
| (unreleased) | 0.1.0 | 0.2.0 | `create_external_link` refuses a second live link to a different external agent. |
| (unreleased) | 0.1.0 | 0.1.0 | First release. |

## License

MIT
