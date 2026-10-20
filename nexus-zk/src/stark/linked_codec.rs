//! Lector estricto del mismo orden LE y longitudes de `codecCertificado`.
//! Se validan cantidades esperadas antes de asignar vectores o ejecutar hashes.

use super::{air::{TracePoint, TransitionStatement}, field::{Felt, Fp2, P},
    fri::{LayerOpening, QueryProof, NUM_QUERIES}, merkle::MerkleProof};
use super::linked::{FriCommitment, LinkedProof, LinkedQuery, VerifyError,
    MAX_CERTIFICATE_BYTES, MIN_ROWS, MAX_ROWS, VERSION, verify_with_profile};
use nexus_core::Hash256;

struct Reader<'a> { bytes: &'a [u8], position: usize }

impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], VerifyError> {
        let end = self.position.checked_add(N).ok_or(VerifyError::Decode)?;
        let slice = self.bytes.get(self.position..end).ok_or(VerifyError::Decode)?;
        let mut result = [0; N];
        result.copy_from_slice(slice);
        self.position = end;
        Ok(result)
    }
    fn integer(&mut self) -> Result<u64, VerifyError> { Ok(u64::from_le_bytes(self.take()?)) }
    fn count(&mut self, expected: usize) -> Result<(), VerifyError> {
        if self.integer()? == expected as u64 { Ok(()) } else { Err(VerifyError::Shape) }
    }
    fn field(&mut self) -> Result<Felt, VerifyError> {
        let value = self.integer()?;
        if value >= P { return Err(VerifyError::NonCanonical); }
        Ok(Felt::new(value))
    }
    fn extension(&mut self) -> Result<Fp2, VerifyError> { Ok(Fp2::new(self.field()?, self.field()?)) }
    fn hashes(&mut self, count: usize) -> Result<Vec<Hash256>, VerifyError> {
        self.count(count)?;
        let mut result = Vec::with_capacity(count);
        for _ in 0..count { result.push(Hash256(self.take()?)); }
        Ok(result)
    }
    fn commitment(&mut self, layers: usize) -> Result<FriCommitment, VerifyError> {
        Ok(FriCommitment { roots: self.hashes(layers)?, final_value: self.extension()? })
    }
    fn fri(&mut self, layers: usize, depth: usize) -> Result<QueryProof, VerifyError> {
        self.count(layers)?;
        let mut result = Vec::with_capacity(layers);
        for i in 0..layers {
            result.push(LayerOpening { left: self.extension()?, right: self.extension()?,
                left_proof: MerkleProof { siblings: self.hashes(depth - i)? },
                right_proof: MerkleProof { siblings: self.hashes(depth - i)? } });
        }
        Ok(QueryProof { layers: result })
    }
}

/// Lee `(TransitionStatement, LinkedProof)` sin sufijos ni campos no canónicos.
pub fn decode_certificate(bytes: &[u8]) -> Result<(TransitionStatement, LinkedProof), VerifyError> {
    if bytes.len() > MAX_CERTIFICATE_BYTES { return Err(VerifyError::Length); }
    let mut reader = Reader { bytes, position: 0 };
    let start = reader.field()?;
    let output = reader.field()?;
    let rows = reader.integer()?;
    if !(MIN_ROWS as u64..=MAX_ROWS as u64).contains(&rows) || !rows.is_power_of_two() {
        return Err(VerifyError::Rows);
    }
    let rows = rows as usize;
    let k = rows.trailing_zeros() as usize;
    let depth = k + 3;
    let statement = TransitionStatement { start, output, steps: rows };
    let version = u16::from_le_bytes(reader.take()?);
    let pow_bits = u32::from_le_bytes(reader.take()?);
    if version != VERSION || (pow_bits != 12 && pow_bits != 20) { return Err(VerifyError::Profile); }
    let trace_root = Hash256(reader.take()?);
    let trace_fri = reader.commitment(k)?;
    let composition_fri = reader.commitment(k + 1)?;
    if trace_fri.roots[0] != trace_root { return Err(VerifyError::TraceRoot); }
    let nonce = reader.integer()?;
    reader.count(NUM_QUERIES)?;
    let mut queries = Vec::with_capacity(NUM_QUERIES);
    for _ in 0..NUM_QUERIES {
        reader.count(6)?;
        let mut trace = Vec::with_capacity(6);
        for _ in 0..6 {
            trace.push(TracePoint { value: reader.field()?, proof: MerkleProof { siblings: reader.hashes(depth)? } });
        }
        queries.push(LinkedQuery { trace, trace_fri: reader.fri(k, depth)?,
            composition_fri: reader.fri(k + 1, depth)? });
    }
    if reader.position != bytes.len() { return Err(VerifyError::TrailingBytes); }
    Ok((statement, LinkedProof { version, pow_bits, trace_root, trace_fri, composition_fri, nonce, queries }))
}

pub fn encode_certificate(statement: &TransitionStatement, proof: &LinkedProof) -> Result<Vec<u8>, VerifyError> {
    let bytes = bincode::serialize(&(statement, proof)).map_err(|_| VerifyError::Decode)?;
    decode_certificate(&bytes)?;
    Ok(bytes)
}

/// La política de trabajo es externa; nunca se rebaja según lo recibido.
pub fn verify_bytes(bytes: &[u8], expected_bits: u32) -> Result<(), VerifyError> {
    let (statement, proof) = decode_certificate(bytes)?;
    verify_with_profile(&statement, &proof, expected_bits)
}
