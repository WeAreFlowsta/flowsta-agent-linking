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
/// Revocation: a Delete of the creation action by one of the two agents.
///
/// This zome is fully generic - no Flowsta-specific fields.
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
        // A lookup link may only be created by one of the two linked agents,
        // and only from one of their keys, to an IsSamePersonEntry that
        // names that key. Anything else would let a lookup answer with an
        // attestation that never named the queried agent.
        FlatOp::RegisterCreateLink {
            base_address,
            target_address,
            link_type,
            action,
            ..
        } => match link_type {
            LinkTypes::AgentToIsSamePerson => {
                let entry = match linked_entry(&target_address)? {
                    Some(e) => e,
                    None => {
                        return Ok(ValidateCallbackResult::Invalid(
                            "AgentToIsSamePerson must point at an IsSamePersonEntry".to_string(),
                        ))
                    }
                };
                Ok(validate_lookup_link(&entry, &base_address, &action.author))
            }
        },
        // Removing a lookup link: the same rule as creating one.
        FlatOp::RegisterDeleteLink {
            original_action,
            target_address,
            link_type,
            action,
            ..
        } => match link_type {
            LinkTypes::AgentToIsSamePerson => {
                let entry = match linked_entry(&target_address)? {
                    Some(e) => e,
                    None => return Ok(ValidateCallbackResult::Valid),
                };
                if action.author != original_action.author && !is_participant(&action.author, &entry) {
                    return Ok(ValidateCallbackResult::Invalid(
                        "Only one of the two linked agents can remove a lookup link".to_string(),
                    ));
                }
                Ok(ValidateCallbackResult::Valid)
            }
        },
        // Revoking an attestation: only one of the two agents named in it
        // may delete it. The original entry is fetched deterministically.
        FlatOp::RegisterDelete(OpDelete { action }) => {
            let entry = must_get_entry(action.deletes_entry_address.clone())?;
            match IsSamePersonEntry::try_from(entry.as_content()) {
                Ok(e) => {
                    if !is_participant(&action.author, &e) {
                        return Ok(ValidateCallbackResult::Invalid(
                            "Only one of the two linked agents can revoke this link".to_string(),
                        ));
                    }
                    Ok(ValidateCallbackResult::Valid)
                }
                // Not one of ours.
                Err(_) => Ok(ValidateCallbackResult::Valid),
            }
        }
        _ => Ok(ValidateCallbackResult::Valid),
    }
}

/// Is `agent` one of the two agents named in the attestation?
pub fn is_participant(agent: &AgentPubKey, entry: &IsSamePersonEntry) -> bool {
    agent == &entry.agent_a || agent == &entry.agent_b
}

/// The rule for a lookup link: its base must be one of the two agents in
/// the entry it points at, and its author must be one of them too.
pub fn validate_lookup_link(
    entry: &IsSamePersonEntry,
    base: &AnyLinkableHash,
    author: &AgentPubKey,
) -> ValidateCallbackResult {
    let base_is_member = base == &AnyLinkableHash::from(entry.agent_a.clone())
        || base == &AnyLinkableHash::from(entry.agent_b.clone());
    if !base_is_member {
        return ValidateCallbackResult::Invalid(
            "A lookup link must start from one of the two agents named in the entry".to_string(),
        );
    }
    if !is_participant(author, entry) {
        return ValidateCallbackResult::Invalid(
            "Only one of the two linked agents can create a lookup link".to_string(),
        );
    }
    ValidateCallbackResult::Valid
}

/// The IsSamePersonEntry a lookup link points at, fetched deterministically
/// through the action that created it. `None` when the target is not an
/// action hash or its record holds no IsSamePersonEntry.
fn linked_entry(target: &AnyLinkableHash) -> ExternResult<Option<IsSamePersonEntry>> {
    let action_hash = match ActionHash::try_from(target.clone()) {
        Ok(h) => h,
        Err(_) => return Ok(None),
    };
    let record = must_get_valid_record(action_hash)?;
    Ok(record
        .entry()
        .as_option()
        .and_then(|e| IsSamePersonEntry::try_from(e).ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(fill: u8) -> AgentPubKey {
        AgentPubKey::from_raw_36(vec![fill; 36])
    }

    fn entry(a: u8, b: u8) -> IsSamePersonEntry {
        let (mut ka, mut kb) = (key(a), key(b));
        if ka > kb {
            std::mem::swap(&mut ka, &mut kb);
        }
        IsSamePersonEntry {
            agent_a: ka,
            agent_b: kb,
            signature_a: Signature([0u8; 64]),
            signature_b: Signature([0u8; 64]),
            created_at: 0,
        }
    }

    #[test]
    fn only_the_two_agents_are_participants() {
        let e = entry(1, 2);
        assert!(is_participant(&key(1), &e));
        assert!(is_participant(&key(2), &e));
        assert!(!is_participant(&key(3), &e));
    }

    #[test]
    fn a_lookup_link_needs_a_member_base_and_a_member_author() {
        let e = entry(1, 2);
        let ok = validate_lookup_link(&e, &AnyLinkableHash::from(key(1)), &key(2));
        assert!(matches!(ok, ValidateCallbackResult::Valid));
        // A stranger's key as the base: the forged-lookup case.
        let bad_base = validate_lookup_link(&e, &AnyLinkableHash::from(key(9)), &key(1));
        assert!(matches!(bad_base, ValidateCallbackResult::Invalid(_)));
        // A member base written by a stranger.
        let bad_author = validate_lookup_link(&e, &AnyLinkableHash::from(key(1)), &key(9));
        assert!(matches!(bad_author, ValidateCallbackResult::Invalid(_)));
    }

    #[test]
    fn keys_sort_the_same_way_as_the_entry_expects() {
        let e = entry(7, 3);
        assert!(e.agent_a < e.agent_b);
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
