use hdi::prelude::*;

/// A pairwise "is-same-person" attestation. Both agents sign the
/// sorted pair of keys, then one of the agents commits this entry
/// to their source chain on the DHT.
///
/// For cross-conductor linking (e.g., Flowsta Vault ↔ third-party app),
/// one agent provides their signature via IPC rather than being on the
/// same DHT. The entry is committed by the agent that IS on the DHT.
///
/// For 3+ agents, create multiple pairwise entries (A↔B, A↔C, B↔C).
/// Revocation: use Holochain's Delete action on the creation action.
///
/// This zome is fully generic — no Flowsta-specific fields.
/// Any Holochain app can include it in their DNA for pairwise agent linking.
///
/// IMPORTANT: All signatures are raw Ed25519 over the 78-byte sorted key pair.
/// This zome uses `verify_signature_raw` (not `verify_signature`) so that
/// external signers (e.g., Flowsta Vault via IPC) can sign with standard
/// Ed25519 libraries without MessagePack encoding.
#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
pub struct IsSamePersonEntry {
    /// First agent in the pair (deterministic: always the lexicographically smaller key)
    pub agent_a: AgentPubKey,

    /// First agent's raw Ed25519 signature over the sorted agent key bytes
    pub signature_a: Signature,

    /// Second agent in the pair (deterministic: always the lexicographically larger key)
    pub agent_b: AgentPubKey,

    /// Second agent's raw Ed25519 signature over the sorted agent key bytes
    pub signature_b: Signature,

    /// Timestamp of when the entry was finalised
    pub created_at: i64,
}

#[hdk_entry_types]
#[unit_enum(UnitEntryTypes)]
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EntryTypes {
    IsSamePerson(IsSamePersonEntry),
}

#[derive(Serialize, Deserialize)]
#[hdk_link_types]
pub enum LinkTypes {
    /// Links from an agent's pubkey to IsSamePersonEntry actions for lookup
    AgentToIsSamePerson,
}

/// Sort two agent keys deterministically and concatenate their raw bytes.
/// Both agents sign this same payload to produce their signatures.
/// Uses raw 39-byte representation (3-byte prefix + 32-byte key + 4-byte checksum)
/// for each key, sorted lexicographically.
///
/// Returns a 78-byte payload (39 bytes per key × 2).
pub fn sorted_agent_pair_bytes(
    agent_a: &AgentPubKey,
    agent_b: &AgentPubKey,
) -> ExternResult<Vec<u8>> {
    let mut keys = vec![agent_a.clone(), agent_b.clone()];
    keys.sort();

    let mut payload = Vec::with_capacity(78); // 39 bytes per key × 2
    for key in &keys {
        payload.extend_from_slice(key.get_raw_39());
    }

    Ok(payload)
}

#[hdk_extern]
pub fn validate(op: Op) -> ExternResult<ValidateCallbackResult> {
    match op.flattened::<EntryTypes, LinkTypes>()? {
        FlatOp::StoreEntry(store_entry) => match store_entry {
            OpEntry::CreateEntry {
                app_entry, action, ..
            } => match app_entry {
                EntryTypes::IsSamePerson(entry) => {
                    validate_is_same_person_entry(&entry, &action.author)
                }
            },
            OpEntry::UpdateEntry {
                app_entry, action, ..
            } => match app_entry {
                EntryTypes::IsSamePerson(entry) => {
                    validate_is_same_person_entry(&entry, &action.author)
                }
            },
            _ => Ok(ValidateCallbackResult::Valid),
        },
        FlatOp::RegisterCreateLink {
            link_type, ..
        } => match link_type {
            LinkTypes::AgentToIsSamePerson => Ok(ValidateCallbackResult::Valid),
        },
        FlatOp::RegisterDeleteLink {
            link_type, ..
        } => match link_type {
            LinkTypes::AgentToIsSamePerson => Ok(ValidateCallbackResult::Valid),
        },
        // Revocation via Delete is handled in the coordinator layer
        // (non-deterministic — cannot check in validation).
        _ => Ok(ValidateCallbackResult::Valid),
    }
}

/// Validate an IsSamePersonEntry:
/// 1. agent_a and agent_b must be different
/// 2. agent_a must be lexicographically smaller than agent_b (canonical ordering)
/// 3. Author must be one of the two agents
/// 4. Both signatures must verify over the raw sorted key pair bytes
///
/// Uses `verify_signature_raw` (not `verify_signature`) for cross-conductor
/// compatibility. External signers (e.g., Flowsta Vault) sign raw bytes with
/// standard Ed25519 libraries. `verify_signature` would MessagePack-encode
/// the payload before verifying, causing a mismatch with externally-produced
/// signatures.
fn validate_is_same_person_entry(
    entry: &IsSamePersonEntry,
    author: &AgentPubKey,
) -> ExternResult<ValidateCallbackResult> {
    if entry.agent_a == entry.agent_b {
        return Ok(ValidateCallbackResult::Invalid(
            "agent_a and agent_b must be different agents".to_string(),
        ));
    }

    if entry.agent_a >= entry.agent_b {
        return Ok(ValidateCallbackResult::Invalid(
            "agent_a must be lexicographically smaller than agent_b".to_string(),
        ));
    }

    if author != &entry.agent_a && author != &entry.agent_b {
        return Ok(ValidateCallbackResult::Invalid(
            "Author must be one of the two agents in the entry".to_string(),
        ));
    }

    let payload = sorted_agent_pair_bytes(&entry.agent_a, &entry.agent_b)?;

    // verify_signature_raw: verifies against the raw bytes without MessagePack encoding.
    // This is critical for cross-conductor linking where one signature comes from
    // an external signer (e.g., Flowsta Vault via IPC using ed25519-dalek).
    if !verify_signature_raw(entry.agent_a.clone(), entry.signature_a.clone(), payload.clone())? {
        return Ok(ValidateCallbackResult::Invalid(
            "signature_a does not verify against agent_a".to_string(),
        ));
    }

    if !verify_signature_raw(entry.agent_b.clone(), entry.signature_b.clone(), payload)? {
        return Ok(ValidateCallbackResult::Invalid(
            "signature_b does not verify against agent_b".to_string(),
        ));
    }

    Ok(ValidateCallbackResult::Valid)
}
