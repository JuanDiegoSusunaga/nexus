//! Bounded public TCP frames. Consensus and query attestations use ML-DSA-65;
//! the transport is plaintext and supplies no confidentiality guarantee.
use bincode::Options;
use nexus_anchor::{bft::{CommittedBlock, Committee, Message, Phase}, MonetaryCounters};
use nexus_core::{AccountState, Address, Block, BlockHeight, Hash256, NexusError, SignatureScheme, SignedTransaction, StateRoot};
use nexus_crypto::{DilithiumKeypair, DilithiumSignature};
use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{net::SocketAddr, time::Duration};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt}, net::TcpStream};

pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
const MAGIC: &[u8; 8] = b"NXSNET04";
fn error(message: impl std::fmt::Display) -> NexusError { NexusError::NetworkError(message.to_string()) }

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, NexusError> {
    bincode::DefaultOptions::new().with_fixint_encoding().with_limit(MAX_FRAME_BYTES as u64)
        .serialize(value).map_err(Into::into)
}
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, NexusError> {
    if bytes.len() > MAX_FRAME_BYTES { return Err(error("Frame exceeds byte limit")); }
    bincode::DefaultOptions::new().with_fixint_encoding().with_limit(MAX_FRAME_BYTES as u64)
        .reject_trailing_bytes().deserialize(bytes).map_err(Into::into)
}
pub async fn read_frame<T: DeserializeOwned>(stream: &mut (impl AsyncRead + Unpin)) -> Result<T, NexusError> {
    let mut header = [0; 12];
    stream.read_exact(&mut header).await.map_err(error)?;
    let length = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
    if &header[..8] != MAGIC || length == 0 || length > MAX_FRAME_BYTES { return Err(error("Invalid frame header/length")); }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await.map_err(error)?;
    decode(&bytes)
}
pub async fn write_frame<T: Serialize>(stream: &mut (impl AsyncWrite + Unpin), value: &T) -> Result<(), NexusError> {
    let bytes = encode(value)?;
    stream.write_all(MAGIC).await.map_err(error)?;
    stream.write_all(&(bytes.len() as u32).to_le_bytes()).await.map_err(error)?;
    stream.write_all(&bytes).await.map_err(error)?;
    stream.flush().await.map_err(error)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request { Poll { next: BlockHeight }, Status, Account(Address), Submit(Box<SignedTransaction>), Commit(BlockHeight) }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope { pub context: Hash256, pub nonce: Hash256, pub request: Request }
impl Envelope {
    pub fn new(committee: &Committee, request: Request) -> Self {
        let mut nonce = [0; 32]; rand::thread_rng().fill_bytes(&mut nonce);
        Self { context: committee.context(), nonce: Hash256::new(nonce), request }
    }
    pub fn request_hash(&self) -> Result<Hash256, NexusError> { Ok(Hash256::hash(&encode(&self.request)?)) }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerUpdate {
    pub height: BlockHeight,
    pub commit: Option<CommittedBlock>,
    pub messages: Vec<Message>,
    pub transactions: Vec<SignedTransaction>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub genesis: Block,
    pub height: BlockHeight, pub round: u32, pub phase: Phase, pub state_root: StateRoot,
    pub money: MonetaryCounters, pub pending: usize,
    pub tip: Option<CommittedBlock>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Reply {
    Poll(PeerUpdate), Status(Status),
    Account { height: BlockHeight, account: Option<AccountState> },
    Submitted { hash: Hash256 }, Commit(Option<CommittedBlock>), Rejected(String),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryAttestation { pub validator: u8, pub signature: Vec<u8> }
impl QueryAttestation {
    fn bytes(committee: &Committee, nonce: Hash256, request: Hash256, reply: Hash256, validator: u8) -> Result<Vec<u8>, NexusError> {
        encode(&(b"NEXUS_PUBLIC_QUERY_V1".as_slice(), nexus_core::PROTOCOL_VERSION,
            committee.context(), nonce, request, reply, validator))
    }
    pub fn sign(committee: &Committee, nonce: Hash256, request: Hash256, reply: Hash256,
        key: &DilithiumKeypair) -> Result<Self, NexusError> {
        let validator = committee.index(key.address())?;
        let signature = key.sign(&Self::bytes(committee, nonce, request, reply, validator)?)?.as_bytes().to_vec();
        Ok(Self { validator, signature })
    }
    pub fn verify(&self, committee: &Committee, nonce: Hash256, request: Hash256, reply: Hash256) -> Result<(), NexusError> {
        let key = committee.keys().get(self.validator as usize).ok_or(NexusError::NotValidator)?;
        let signature = DilithiumSignature::from_bytes(self.signature.clone(), SignatureScheme::Dilithium3)?;
        if !key.verify(&Self::bytes(committee, nonce, request, reply, self.validator)?, &signature)? {
            return Err(NexusError::InvalidValidatorSignature);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response { pub context: Hash256, pub nonce: Hash256, pub reply: Reply, pub attestation: Option<QueryAttestation> }
impl Response {
    pub fn verify(&self, committee: &Committee, request: &Envelope) -> Result<(), NexusError> {
        if self.context != committee.context() || request.context != self.context || self.nonce != request.nonce {
            return Err(error("Response context or request nonce differs"));
        }
        if !matches!((&request.request, &self.reply), (Request::Poll { .. }, Reply::Poll(_))
            | (Request::Status, Reply::Status(_)) | (Request::Account(_), Reply::Account { .. })
            | (Request::Submit(_), Reply::Submitted { .. }) | (Request::Commit(_), Reply::Commit(_))
            | (_, Reply::Rejected(_))) {
            return Err(error("Reply kind does not match request"));
        }
        if let Some(attestation) = &self.attestation {
            attestation.verify(committee, self.nonce, request.request_hash()?, Hash256::hash(&encode(&self.reply)?))?;
        } else if !matches!((&request.request, &self.reply),
            (Request::Poll { .. }, Reply::Poll(_)) | (Request::Commit(_), Reply::Commit(_))) {
            return Err(error("Query requires a validator attestation"));
        }
        match &self.reply {
            Reply::Poll(update) => {
                if update.messages.len() > 64 || update.transactions.len() > 16 { return Err(error("Peer update exceeds item limits")); }
                if let Some(commit) = &update.commit {
                    commit.verify(committee)?;
                    if !matches!(&request.request, Request::Poll { next } if *next == commit.block().height()) {
                        return Err(error("Poll returned a different requested height"));
                    }
                }
            }
            Reply::Commit(Some(commit)) => {
                commit.verify(committee)?;
                if !matches!(&request.request, Request::Commit(height) if *height == commit.block().height()) {
                    return Err(error("Commit returned a different requested height"));
                }
            }
            Reply::Status(status) => {
                if status.genesis.hash() != committee.genesis() || !status.genesis.body.transactions.is_empty()
                    || !status.genesis.body.signatures.is_empty() || status.genesis.height() != BlockHeight::GENESIS {
                    return Err(error("Status genesis differs"));
                }
                if let Some(commit) = &status.tip {
                    commit.verify(committee)?;
                    if commit.block().height() != status.height || commit.block().header.state_root != status.state_root.0 {
                        return Err(error("Status does not match its tip certificate"));
                    }
                } else if status.height != BlockHeight::GENESIS || status.state_root.0 != status.genesis.header.state_root {
                    return Err(error("Status is missing or contradicts its genesis/tip"));
                }
            }
            _ => (),
        }
        Ok(())
    }
}

pub async fn exchange(address: SocketAddr, committee: &Committee, request: Request, timeout: Duration) -> Result<Response, NexusError> {
    let envelope = Envelope::new(committee, request);
    tokio::time::timeout(timeout, async {
        let mut stream = TcpStream::connect(address).await.map_err(error)?;
        stream.set_nodelay(true).map_err(error)?;
        write_frame(&mut stream, &envelope).await?;
        let response: Response = read_frame(&mut stream).await?;
        response.verify(committee, &envelope)?;
        Ok(response)
    }).await.map_err(|_| error("TCP request deadline exceeded"))?
}
