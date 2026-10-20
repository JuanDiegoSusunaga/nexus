//! Contrastes finitos del contrato de Lean; no prueba universal de refinamiento.
use nexus_zk::stark::{linked::{self, VerifyError}, linked_codec::{decode_certificate, encode_certificate, verify_bytes},
    field::P};
use std::path::PathBuf;

fn corpus(profile: &str, name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../Documentos/06-Evidencia-TG2/2026-09-22/R4-FRI-vinculado")
        .join(format!("corpus-{profile}/{name}.bin"));
    std::fs::read(path).expect("El corpus público conservado debe estar disponible")
}

#[test]
fn los_catorce_certificados_historicos_conservan_su_resultado_y_bytes() {
    for (profile, bits) in [("debug", 12), ("release", 20)] {
        for rows in [16, 64, 256, 4096] {
            let bytes = corpus(profile, &format!("honesto-{rows}"));
            let (statement, proof) = decode_certificate(&bytes).unwrap();
            assert_eq!(encode_certificate(&statement, &proof).unwrap(), bytes);
            assert_eq!(verify_bytes(&bytes, bits), Ok(()));
            assert_eq!(verify_bytes(&bytes, if bits == 12 { 20 } else { 12 }), Err(VerifyError::Profile));
        }
        for rows in [16, 32, 64] {
            let bytes = corpus(profile, &format!("lejano-{rows}"));
            assert_eq!(verify_bytes(&bytes, bits), Err(VerifyError::TraceFri));
        }
    }
}

#[test]
fn lector_rechaza_truncados_sufijos_cantidades_hostiles_y_campos_no_canonicos() {
    let bytes = corpus("debug", "honesto-16");
    for size in [0, 1, 23, 62, bytes.len() / 2, bytes.len() - 1] {
        assert!(decode_certificate(&bytes[..size]).is_err());
    }
    let mut changed = bytes.clone();
    changed.push(0);
    assert!(matches!(decode_certificate(&changed), Err(VerifyError::TrailingBytes)));
    for offset in [0, 8] {
        let mut changed = bytes.clone();
        changed[offset..offset + 8].copy_from_slice(&P.to_le_bytes());
        assert!(matches!(decode_certificate(&changed), Err(VerifyError::NonCanonical)));
    }
    let mut changed = bytes.clone();
    changed[62..70].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(matches!(decode_certificate(&changed), Err(VerifyError::Shape)));
    assert!(matches!(decode_certificate(&vec![0; linked::MAX_CERTIFICATE_BYTES + 1]), Err(VerifyError::Length)));
}

#[test]
fn lector_acota_filas_version_y_perfil_antes_de_asignar_vectores() {
    let bytes = corpus("debug", "honesto-16");
    for rows in [0, 4, 8, 17, 8192, u64::MAX] {
        let mut changed = bytes.clone();
        changed[16..24].copy_from_slice(&rows.to_le_bytes());
        assert!(matches!(decode_certificate(&changed), Err(VerifyError::Rows)));
    }
    let mut changed = bytes.clone();
    changed[24..26].copy_from_slice(&2u16.to_le_bytes());
    assert!(matches!(decode_certificate(&changed), Err(VerifyError::Profile)));
    changed = bytes;
    changed[26..30].copy_from_slice(&0u32.to_le_bytes());
    assert!(matches!(decode_certificate(&changed), Err(VerifyError::Profile)));
}

#[test]
fn verificacion_tipificada_rechaza_formas_y_enlaces_antes_de_indexar() {
    let bytes = corpus("debug", "honesto-16");
    let (statement, proof) = decode_certificate(&bytes).unwrap();
    for case in 0..7 {
        let mut changed = proof.clone();
        match case {
            0 => changed.trace_fri.roots.clear(),
            1 => { changed.composition_fri.roots.pop(); },
            2 => changed.queries.clear(),
            3 => changed.queries[0].trace.clear(),
            4 => changed.queries[0].trace_fri.layers.clear(),
            5 => changed.queries[0].composition_fri.layers[0].left_proof.siblings.clear(),
            _ => changed.trace_fri.roots[0].0[0] ^= 1,
        }
        assert!(linked::verify_with_profile(&statement, &changed, 12).is_err());
    }
}
