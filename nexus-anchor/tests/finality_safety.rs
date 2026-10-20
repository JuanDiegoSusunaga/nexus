//! Finality follows the exact weighted quorum and authenticated ancestry contract.
use nexus_anchor::{FinalityGadget, Validator, ValidatorSet};
use nexus_anchor::finality::{finality_signing_bytes, FinalityVote};
use nexus_core::{Amount, Block, BlockBody, BlockHeader, BlockHeight, Hash256, Layer, SignatureScheme};
use nexus_crypto::DilithiumKeypair;

fn fixture() -> (FinalityGadget, Vec<DilithiumKeypair>) {
    let keys: Vec<_> = (0..3).map(|_| DilithiumKeypair::generate(SignatureScheme::Dilithium3).unwrap()).collect();
    let mut set = ValidatorSet::new();
    for key in &keys {
        set.add_validator(Validator::new(key.address(), key.public_key().as_bytes().to_vec(), Amount(1))).unwrap();
        set.activate_validator(&key.address()).unwrap();
    }
    (FinalityGadget::with_validator_set(set), keys)
}

fn vote(key: &DilithiumKeypair, block: &Block) -> FinalityVote {
    FinalityVote { validator: key.address(), weight: 1,
        signature: key.sign(&finality_signing_bytes(block.hash(), block.height()).unwrap()).unwrap().as_bytes().to_vec() }
}

fn child(parent: &Block, tag: u8) -> Block {
    let mut header = BlockHeader::new(BlockHeight(parent.height().0 + 1), parent.hash(),
        nexus_core::Address::ZERO, Layer::Anchor);
    header.extra_data = vec![tag];
    Block::new(header, BlockBody::new(vec![]))
}

#[test]
fn two_thirds_duplicates_and_untrusted_totals_cannot_finalize() {
    let (mut gadget, keys) = fixture();
    let block = child(&Block::genesis(Layer::Anchor), 1);
    gadget.add_block(block.clone());
    for key in &keys[..2] { gadget.add_vote(vote(key, &block), block.hash()).unwrap(); }
    assert!(!gadget.add_vote(vote(&keys[0], &block), block.hash()).unwrap());
    assert!(gadget.try_finalize(block.hash(), 3).unwrap().is_none());
    assert!(gadget.try_finalize(block.hash(), 2).unwrap().is_none());
    gadget.add_vote(vote(&keys[2], &block), block.hash()).unwrap();
    let certificate = gadget.try_finalize(block.hash(), 3).unwrap().unwrap();
    assert_eq!(certificate.justification.threshold, 3);
    assert_eq!(certificate.justification.total_weight, 3);
}

#[test]
fn rejects_forged_signatures_weights_and_target_replays() {
    let (mut gadget, keys) = fixture();
    let a = child(&Block::genesis(Layer::Anchor), 1);
    let b = child(&Block::genesis(Layer::Anchor), 2);
    gadget.add_block(a.clone());
    gadget.add_block(b.clone());
    let mut fake = vote(&keys[0], &a);
    fake.signature.fill(0);
    assert!(gadget.add_vote(fake, a.hash()).is_err());
    let mut wrong_weight = vote(&keys[0], &a);
    wrong_weight.weight = u128::MAX;
    assert!(gadget.add_vote(wrong_weight, a.hash()).is_err());
    assert!(gadget.add_vote(vote(&keys[0], &a), b.hash()).is_err());
    assert_eq!(gadget.vote_count(&a.hash()), 0);
    assert_eq!(gadget.vote_count(&b.hash()), 0);
}

#[test]
fn authority_changes_cannot_rewrite_a_pending_block_snapshot() {
    let (mut gadget, keys) = fixture();
    let block = child(&Block::genesis(Layer::Anchor), 1);
    gadget.add_block(block.clone());
    gadget.set_validator_set(ValidatorSet::new());
    gadget.add_block(block.clone());
    for key in &keys { gadget.add_vote(vote(key, &block), block.hash()).unwrap(); }
    assert!(gadget.try_finalize(block.hash(), 3).unwrap().is_some());
    let later = child(&block, 2);
    gadget.add_block(later.clone());
    assert!(gadget.add_vote(vote(&keys[0], &later), later.hash()).is_err());
    assert!(gadget.try_finalize(later.hash(), 0).unwrap().is_none());
}

#[test]
fn quorum_cannot_finalize_a_fork_that_does_not_descend_from_the_anchor() {
    let (mut gadget, keys) = fixture();
    let genesis = Block::genesis(Layer::Anchor);
    let a = child(&genesis, 1);
    gadget.add_block(a.clone());
    for key in &keys { gadget.add_vote(vote(key, &a), a.hash()).unwrap(); }
    assert!(gadget.try_finalize(a.hash(), 3).unwrap().is_some());
    let fork = child(&child(&genesis, 2), 3);
    gadget.add_block(fork.clone());
    for key in &keys { gadget.add_vote(vote(key, &fork), fork.hash()).unwrap(); }
    assert!(gadget.try_finalize(fork.hash(), 3).unwrap().is_none());
    let descendant = child(&a, 4);
    gadget.add_block(descendant.clone());
    for key in &keys { gadget.add_vote(vote(key, &descendant), descendant.hash()).unwrap(); }
    assert!(gadget.try_finalize(descendant.hash(), 3).unwrap().is_some());
}

#[test]
fn zero_authority_and_missing_ancestry_never_create_a_certificate() {
    let (mut gadget, keys) = fixture();
    let mut block = child(&Block::genesis(Layer::Anchor), 1);
    block.header.parent_hash = Hash256::hash(b"unknown parent");
    gadget.add_block(block.clone());
    for key in &keys { gadget.add_vote(vote(key, &block), block.hash()).unwrap(); }
    assert!(gadget.try_finalize(block.hash(), 3).unwrap().is_none());
    let mut empty = FinalityGadget::new();
    empty.add_block(block.clone());
    assert!(empty.add_vote(vote(&keys[0], &block), block.hash()).is_err());
    assert!(empty.try_finalize(block.hash(), 0).unwrap().is_none());
}
