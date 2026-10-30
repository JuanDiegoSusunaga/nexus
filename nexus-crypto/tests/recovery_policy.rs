use nexus_core::{Address, ChainId, Hash256, SignatureScheme, Timestamp};
use nexus_crypto::{DilithiumKeypair, DilithiumSignature, EmergencyFreezeRequest, RecoveryAuthority, RecoveryPolicy};

fn key(seed: u8) -> DilithiumKeypair {
    DilithiumKeypair::from_seed(&[seed; 32], SignatureScheme::Dilithium3).unwrap()
}
fn domain() -> Hash256 { Hash256::hash(b"deployment-a") }
fn identity() -> Address { key(1).address() }
fn authority() -> RecoveryAuthority { RecoveryAuthority { identity: identity(), public_key: key(2).public_key().clone() } }
fn request() -> EmergencyFreezeRequest {
    EmergencyFreezeRequest::sign(ChainId::LOCAL, domain(), identity(), Timestamp(100), Timestamp(200), &key(2)).unwrap()
}

#[test]
fn configuration_requires_distinct_valid_authorities_even_when_deserialized() {
    let policy = RecoveryPolicy::new(domain(), vec![authority()]).unwrap();
    let restored: RecoveryPolicy = bincode::deserialize(&bincode::serialize(&policy).unwrap()).unwrap();
    restored.verify_freeze(&request(), ChainId::LOCAL, Timestamp(150)).unwrap();
    assert!(RecoveryPolicy::new(Hash256::ZERO, vec![authority()]).is_err());
    assert!(RecoveryPolicy::new(domain(), vec![authority(), authority()]).is_err());
    let same = RecoveryAuthority { identity: identity(), public_key: key(1).public_key().clone() };
    assert!(RecoveryPolicy::new(domain(), vec![same.clone()]).is_err());
    let bad = bincode::serialize(&(domain(), vec![same])).unwrap();
    assert!(bincode::deserialize::<RecoveryPolicy>(&bad).is_err());
    let overlap = RecoveryAuthority { identity: key(2).address(), public_key: key(3).public_key().clone() };
    assert!(RecoveryPolicy::new(domain(), vec![authority(), overlap]).is_err());
    assert!(RecoveryPolicy::default().verify_freeze(&request(), ChainId::LOCAL, Timestamp(150)).is_err());
}

#[test]
fn signed_freezes_bind_all_fields_and_enforce_submission_window() {
    let policy = RecoveryPolicy::new(domain(), vec![authority()]).unwrap();
    let original = request();
    policy.verify_freeze(&original, ChainId::LOCAL, Timestamp(100)).unwrap();
    policy.verify_freeze(&original, ChainId::LOCAL, Timestamp(200)).unwrap();
    assert!(policy.verify_freeze(&original, ChainId::LOCAL, Timestamp(99)).is_err());
    assert!(policy.verify_freeze(&original, ChainId::LOCAL, Timestamp(201)).is_err());
    let mut variants = Vec::new();
    let mut changed = original.clone(); changed.body.version = 2; variants.push(changed);
    let mut changed = original.clone(); changed.body.chain_id = ChainId::TESTNET; variants.push(changed);
    let mut changed = original.clone(); changed.body.deployment = Hash256::hash(b"deployment-b"); variants.push(changed);
    let mut changed = original.clone(); changed.body.identity = key(3).address(); variants.push(changed);
    let mut changed = original.clone(); changed.body.issued_at = Timestamp(101); variants.push(changed);
    let mut changed = original.clone(); changed.body.expires_at = Timestamp(199); variants.push(changed);
    let mut changed = original.clone();
    let mut signature = changed.signature.as_bytes().to_vec(); signature[0] ^= 1;
    changed.signature = DilithiumSignature::from_bytes(signature, changed.signature.scheme()).unwrap(); variants.push(changed);
    for changed in variants { assert!(policy.verify_freeze(&changed, ChainId::LOCAL, Timestamp(150)).is_err()); }
    assert!(policy.verify_freeze(&original, ChainId::TESTNET, Timestamp(150)).is_err());
    let other = RecoveryPolicy::new(Hash256::hash(b"deployment-b"), vec![authority()]).unwrap();
    assert!(other.verify_freeze(&original, ChainId::LOCAL, Timestamp(150)).is_err());
}

#[test]
fn operational_keys_and_generic_signatures_do_not_authorize_emergencies() {
    let policy = RecoveryPolicy::new(domain(), vec![authority()]).unwrap();
    for signer in [key(1), key(3)] {
        let forged = EmergencyFreezeRequest::sign(ChainId::LOCAL, domain(), identity(), Timestamp(100), Timestamp(200), &signer).unwrap();
        assert!(policy.verify_freeze(&forged, ChainId::LOCAL, Timestamp(150)).is_err());
    }
    let mut generic = request(); generic.signature = key(2).sign(b"freeze").unwrap();
    assert!(policy.verify_freeze(&generic, ChainId::LOCAL, Timestamp(150)).is_err());
    assert!(EmergencyFreezeRequest::sign(ChainId::LOCAL, domain(), identity(), Timestamp(200), Timestamp(200), &key(2)).is_err());
}
