use hdk::prelude::*;
use flowsta_agent_linking_integrity::*;

#[hdk_dependent_entry_types]
enum EntryZomes {
    Integrity(flowsta_agent_linking_integrity::EntryTypes),
}

// ── Input/Output Types ──────────────────────────────────────────────

/// Input for create_external_link: link a local agent to an external agent
/// whose signature was obtained out-of-band (e.g., via Flowsta Vault IPC).
#[derive(Serialize, Deserialize, Debug)]
pub struct ExternalLinkInput {
    /// The external agent's public key (e.g., from Flowsta Vault)
    pub external_agent: AgentPubKey,
    /// The external agent's raw Ed25519 signature over the sorted key pair bytes
    pub external_signature: Signature,
}

/// Input for the are_agents_linked function
#[derive(Serialize, Deserialize, Debug)]
pub struct AgentPair {
    pub agent_a: AgentPubKey,
    pub agent_b: AgentPubKey,
}

// ── Public Functions ────────────────────────────────────────────────

/// Create an IsSamePersonEntry linking the calling agent to an external agent.
///
/// Designed for cross-conductor identity linking where the external agent
/// (e.g., Flowsta Vault) provides its signature via IPC rather than being
/// on the same DHT.
///
/// The calling agent's conductor signs with `sign_raw`, and the external
/// agent's signature is verified with `verify_signature_raw`. Both sign
/// over the raw 78-byte sorted key pair — no MessagePack encoding.
///
/// Security: The external agent's signature is verified before committing.
/// The entry passes the same integrity validation as any IsSamePersonEntry.
#[hdk_extern]
pub fn create_external_link(input: ExternalLinkInput) -> ExternResult<ActionHash> {
    let my_pub_key = agent_info()?.agent_initial_pubkey;

    if my_pub_key == input.external_agent {
        return Err(wasm_error!("Cannot link an agent to itself"));
    }

    // Compute the canonical sorted key pair payload (78 bytes)
    let payload = sorted_agent_pair_bytes(&my_pub_key, &input.external_agent)?;

    // Verify the external agent's signature (raw Ed25519, no MessagePack)
    if !verify_signature_raw(
        input.external_agent.clone(),
        input.external_signature.clone(),
        payload.clone(),
    )? {
        return Err(wasm_error!(
            "External agent's signature is invalid"
        ));
    }

    // Sign our half with sign_raw (raw bytes, no MessagePack)
    let my_signature = sign_raw(my_pub_key.clone(), payload)?;

    // Construct the IsSamePersonEntry with canonical ordering (agent_a < agent_b)
    let mut keys = vec![
        (my_pub_key.clone(), my_signature),
        (input.external_agent.clone(), input.external_signature),
    ];
    keys.sort_by(|a, b| a.0.cmp(&b.0));

    let now = sys_time()?;
    let now_secs = now.as_seconds_and_nanos().0;

    let entry = IsSamePersonEntry {
        agent_a: keys[0].0.clone(),
        signature_a: keys[0].1.clone(),
        agent_b: keys[1].0.clone(),
        signature_b: keys[1].1.clone(),
        created_at: now_secs,
    };

    // Commit the entry
    let entry_hash = create_entry(&EntryZomes::Integrity(
        EntryTypes::IsSamePerson(entry.clone()),
    ))?;

    // Create lookup links from BOTH agents' pubkeys to the entry.
    // The external agent's pubkey gets a link too — this allows anyone on the DHT
    // to look up "which local agents are linked to this Flowsta identity?"
    create_link(
        entry.agent_a.clone(),
        entry_hash.clone(),
        LinkTypes::AgentToIsSamePerson,
        (),
    )?;
    create_link(
        entry.agent_b.clone(),
        entry_hash.clone(),
        LinkTypes::AgentToIsSamePerson,
        (),
    )?;

    Ok(entry_hash)
}

/// Get all agents linked to a given agent (non-deleted entries only).
/// Follows links from the agent's pubkey to IsSamePersonEntry entries,
/// filters out deleted (revoked) entries, and returns the OTHER agent
/// from each pair.
///
/// Works for both local and external agent pubkeys — you can query
/// "which local agents are linked to this Flowsta identity?" by passing
/// the Flowsta Vault's agent pubkey.
#[hdk_extern]
pub fn get_linked_agents(agent: AgentPubKey) -> ExternResult<Vec<AgentPubKey>> {
    let links = get_links(
        LinkQuery::try_new(agent.clone(), LinkTypes::AgentToIsSamePerson)?,
        GetStrategy::default(),
    )?;

    let mut linked_agents: Vec<AgentPubKey> = Vec::new();

    for link in links {
        let action_hash = match ActionHash::try_from(link.target.clone()) {
            Ok(hash) => hash,
            Err(_) => continue,
        };

        // Get the entry details to check for Deletes (revocation)
        let details = match get_details(action_hash, GetOptions::default())? {
            Some(details) => details,
            None => continue,
        };

        match details {
            Details::Record(record_details) => {
                // Skip deleted (revoked) entries
                if !record_details.deletes.is_empty() {
                    continue;
                }

                // Extract the entry and find the OTHER agent
                if let Some(entry) = record_details.record.entry().as_option() {
                    if let Ok(is_same_person) = IsSamePersonEntry::try_from(entry) {
                        let other_agent = if is_same_person.agent_a == agent {
                            is_same_person.agent_b.clone()
                        } else {
                            is_same_person.agent_a.clone()
                        };

                        if !linked_agents.contains(&other_agent) {
                            linked_agents.push(other_agent);
                        }
                    }
                }
            }
            _ => continue,
        }
    }

    Ok(linked_agents)
}

/// Check if two specific agents are linked (non-deleted entry exists).
#[hdk_extern]
pub fn are_agents_linked(agents: AgentPair) -> ExternResult<bool> {
    let linked = get_linked_agents(agents.agent_a.clone())?;
    Ok(linked.contains(&agents.agent_b))
}

/// Revoke a link by deleting the IsSamePersonEntry creation action.
/// Only one of the two agents in the entry can revoke it (the one
/// on this DHT — the external agent cannot call this function).
/// Returns the ActionHash of the Delete action.
#[hdk_extern]
pub fn revoke_link(entry_action_hash: ActionHash) -> ExternResult<ActionHash> {
    let my_pub_key = agent_info()?.agent_initial_pubkey;

    // Get the entry to verify the caller is one of the agents
    let record = get(entry_action_hash.clone(), GetOptions::default())?
        .ok_or(wasm_error!("Entry not found"))?;

    let entry = record
        .entry()
        .as_option()
        .ok_or(wasm_error!("No entry data found"))?;

    let is_same_person = IsSamePersonEntry::try_from(entry)
        .map_err(|_| wasm_error!("Entry is not an IsSamePersonEntry"))?;

    if my_pub_key != is_same_person.agent_a && my_pub_key != is_same_person.agent_b {
        return Err(wasm_error!(
            "Only one of the two linked agents can revoke this link"
        ));
    }

    // Delete the original creation action
    let delete_hash = delete_entry(entry_action_hash)?;

    Ok(delete_hash)
}
