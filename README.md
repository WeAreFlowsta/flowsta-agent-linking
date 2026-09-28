# Flowsta Agent Linking

Reusable Holochain zome pair for cross-conductor agent identity linking. Allows users to prove that two agent keys (on different conductors/DHTs) belong to the same person via pairwise Ed25519 signatures.

Designed for third-party Holochain apps that authenticate users through [Flowsta Vault](https://flowsta.com/vault) — but the zome is fully generic and can be used for any pairwise agent linking scenario.

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

```toml
# In your integrity zome's Cargo.toml
[dependencies]
flowsta-agent-linking-integrity = "0.1"

# In your coordinator zome's Cargo.toml
[dependencies]
flowsta-agent-linking-coordinator = "0.1"
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
    external_signature: base64ToBytes(result.payload.vaultSignature),
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
// Returns: [vaultAgentPubKey] — Flowsta identity verified on-DHT
```

## Zome Functions

| Function | Input | Output | Purpose |
|---|---|---|---|
| `create_external_link` | `{ external_agent, external_signature }` | `ActionHash` | Link local agent to external (Vault) agent |
| `get_linked_agents` | `AgentPubKey` | `Vec<AgentPubKey>` | Query all linked agents (non-deleted) |
| `are_agents_linked` | `{ agent_a, agent_b }` | `bool` | Check if two agents are linked |
| `revoke_link` | `ActionHash` | `ActionHash` | Delete the pairwise entry |

**One agent, one external identity (0.2.0).** `create_external_link` refuses when the calling agent already holds a live link to a *different* external agent: a second attestation would publish a claim that two people are one. Linking the same external agent again is allowed (reinstall, restore). To move an agent to another identity on purpose, `revoke_link` the old entry first. Flowsta Vault 1.5.0 applies the same rule on its side before showing any dialog, and its identity switcher is where apps meet this case.

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

V0.1.x targets Holochain 0.6.0 (`hdi = 0.7.0`, `hdk = 0.6.0`).

## License

MIT
