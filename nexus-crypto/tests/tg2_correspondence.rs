//! Correspondencia funcional del envoltorio TG2 con la API de fips204 0.4.6.
//! Compartir backend no constituye validación independiente ni prueba de seguridad.
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87, Ph};
use nexus_core::SignatureScheme;
use nexus_crypto::dilithium::{DilithiumKeypair, DilithiumSignature};
use zeroize::Zeroizing;

macro_rules! comprobar_perfil {
    ($backend:ident, $scheme:expr) => {{
        // Datos públicos de ensayo, ajenos a cualquier clave de despliegue.
        let semilla = Zeroizing::new([41u8; 32]);
        let mensaje = b"NEXUS TG2 R1: correspondencia de perfil";
        let contexto = b"NEXUS-TG2-R1";
        let envoltorio = DilithiumKeypair::from_seed(&semilla, $scheme).unwrap();
        let (publica, privada) = $backend::KG::keygen_from_seed(&semilla);
        assert_eq!(envoltorio.public_key().as_bytes(), &publica.clone().into_bytes());

        // La ruta ordinaria firma en modo puro y con contexto vacío.
        let firma = envoltorio.sign(mensaje).unwrap();
        let bytes: [u8; $backend::SIG_LEN] = firma.as_bytes().try_into().unwrap();
        assert!(publica.verify(mensaje, &bytes, b""));
        assert!(!publica.verify(mensaje, &bytes, contexto));
        assert!(!publica.hash_verify(mensaje, &bytes, b"", &Ph::SHA512));
        assert!(!publica.verify(b"mensaje modificado", &bytes, b""));

        // La verificación acepta firmas deterministas válidas del mismo perfil.
        let determinista = privada.try_sign_with_seed(&[0u8; 32], mensaje, b"").unwrap();
        let repetida = privada.try_sign_with_seed(&[0u8; 32], mensaje, b"").unwrap();
        assert_eq!(determinista, repetida);
        let firma = DilithiumSignature::from_bytes(determinista.to_vec(), $scheme).unwrap();
        assert!(envoltorio.public_key().verify(mensaje, &firma).unwrap());

        // Una firma creada para otro contexto o para HashML-DSA queda separada.
        let contextual = privada.try_sign_with_seed(&[0u8; 32], mensaje, contexto).unwrap();
        let firma = DilithiumSignature::from_bytes(contextual.to_vec(), $scheme).unwrap();
        assert!(!envoltorio.public_key().verify(mensaje, &firma).unwrap());
        let prehash = privada.try_hash_sign_with_seed(
            &[0u8; 32], mensaje, b"", &Ph::SHA512
        ).unwrap();
        let firma = DilithiumSignature::from_bytes(prehash.to_vec(), $scheme).unwrap();
        assert!(!envoltorio.public_key().verify(mensaje, &firma).unwrap());
    }};
}

#[test]
fn correspondencia_ml_dsa_44() {
    comprobar_perfil!(ml_dsa_44, SignatureScheme::Dilithium2);
}

#[test]
fn correspondencia_ml_dsa_65() {
    comprobar_perfil!(ml_dsa_65, SignatureScheme::Dilithium3);
}

#[test]
fn correspondencia_ml_dsa_87() {
    comprobar_perfil!(ml_dsa_87, SignatureScheme::Dilithium5);
}
