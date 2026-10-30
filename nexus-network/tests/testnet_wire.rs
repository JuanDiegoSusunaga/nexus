use nexus_anchor::bft::Committee;
use nexus_core::{Address, Block, BlockHeight, Hash256, Layer, SignatureScheme};
use nexus_crypto::DilithiumKeypair;
use nexus_network::testnet::{self as wire, Envelope, QueryAttestation, Reply, Request, Response};
use tokio::io::AsyncWriteExt;

fn fixture() -> (Committee, Vec<DilithiumKeypair>) {
    let mut keys: Vec<_> = (1..=4).map(|seed| DilithiumKeypair::from_seed(&[seed; 32], SignatureScheme::Dilithium3).unwrap()).collect();
    keys.sort_by_key(|key| key.address().0);
    let committee = Committee::new(Block::genesis(Layer::Anchor).hash(), Hash256::new([1; 32]),
        keys.iter().map(|key| key.public_key().clone()).collect()).unwrap();
    (committee, keys)
}
fn response(committee: &Committee, key: &DilithiumKeypair, request: &Envelope, reply: Reply) -> Response {
    let proof = QueryAttestation::sign(committee, request.nonce, request.request_hash().unwrap(),
        Hash256::hash(&wire::encode(&reply).unwrap()), key).unwrap();
    Response { context: committee.context(), nonce: request.nonce, reply, attestation: Some(proof) }
}

#[test]
fn a_response_attestation_binds_query_nonce_context_body_and_validator() {
    let (committee, keys) = fixture();
    let request = Envelope::new(&committee, Request::Account(Address::ZERO));
    let original = response(&committee, &keys[0], &request, Reply::Account { height: BlockHeight(0), account: None });
    original.verify(&committee, &request).unwrap();
    for case in 0..5 {
        let mut altered = original.clone();
        match case {
            0 => altered.nonce = Hash256::ZERO,
            1 => altered.context = Hash256::ZERO,
            2 => altered.attestation.as_mut().unwrap().validator = 1,
            3 => altered.reply = Reply::Account { height: BlockHeight(100), account: None },
            _ => altered.attestation = None,
        }
        assert!(altered.verify(&committee, &request).is_err());
    }
    let mut different = request.clone(); different.request = Request::Account(Address::new([7; 32]));
    assert!(original.verify(&committee, &different).is_err());
    let wrong_kind = response(&committee, &keys[0], &request, Reply::Commit(None));
    assert!(wrong_kind.verify(&committee, &request).is_err());
}

#[tokio::test]
async fn frame_limits_and_canonical_payload_are_checked_before_acceptance() {
    let (committee, _) = fixture();
    let request = Envelope::new(&committee, Request::Status);
    let (mut left, mut right) = tokio::io::duplex(4096);
    wire::write_frame(&mut left, &request).await.unwrap();
    let decoded: Envelope = wire::read_frame(&mut right).await.unwrap();
    assert_eq!(decoded.nonce, request.nonce);
    let mut extra = wire::encode(&request).unwrap(); extra.push(0);
    assert!(wire::decode::<Envelope>(&extra).is_err());
    for length in [0u32, (wire::MAX_FRAME_BYTES + 1) as u32, u32::MAX] {
        let (mut left, mut right) = tokio::io::duplex(64);
        left.write_all(b"NXSNET04").await.unwrap();
        left.write_all(&length.to_le_bytes()).await.unwrap();
        assert!(wire::read_frame::<Envelope>(&mut right).await.is_err());
    }
}

#[test]
fn one_validator_attestation_cannot_invent_a_finalized_tip_without_a_quorum_certificate() {
    let (committee, keys) = fixture();
    let request = Envelope::new(&committee, Request::Status);
    let status = wire::Status { genesis: Block::genesis(Layer::Anchor), height: BlockHeight(1), round: 0,
        phase: nexus_anchor::bft::Phase::Propose, state_root: Default::default(), pending: 0, tip: None,
        money: nexus_anchor::MonetaryCounters { issued: nexus_core::Amount::ZERO,
            burned: nexus_core::Amount::ZERO, fees_collected: nexus_core::Amount::ZERO } };
    let reply = response(&committee, &keys[0], &request, Reply::Status(status));
    assert!(reply.verify(&committee, &request).is_err());
}

#[test]
fn public_transaction_id_commits_sender_public_key_and_signature_profile() {
    use nexus_core::{Amount, ChainId, Nonce, Transaction};
    use nexus_crypto::Signer;
    let (committee, keys) = fixture();
    let mut transaction = Transaction::transfer(ChainId::TESTNET, Nonce(0), keys[1].address(), Amount(1), 200_000, Amount(1));
    transaction.network_domain = Some(committee.network_domain());
    let signed = keys[0].sign_transaction(transaction).unwrap();
    for case in 0..3 {
        let mut altered = signed.clone();
        match case { 0 => altered.sender = Address::ZERO, 1 => altered.public_key[0] ^= 1,
            _ => altered.signature.scheme = SignatureScheme::Dilithium2 }
        assert_ne!(signed.hash(), altered.hash());
    }
}
