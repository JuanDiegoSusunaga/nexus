//! Comprobaciones TG2 de representación y capacidad de firma desde semilla.
//! No inspeccionan memoria liberada ni acreditan el borrado físico del sistema.
use nexus_core::SignatureScheme;
use nexus_crypto::dilithium::DilithiumKeypair;
use zeroize::Zeroizing;

#[test]
fn serialized_keypair_includes_public_material_and_headers() {
    for (scheme, public_len, private_len) in [
        (SignatureScheme::Dilithium2, 1312, 2560),
        (SignatureScheme::Dilithium3, 1952, 4032),
        (SignatureScheme::Dilithium5, 2592, 4896),
    ] {
        let seed = Zeroizing::new([73; 32]);
        let key = DilithiumKeypair::from_seed(&seed, scheme).unwrap();
        let encoded = Zeroizing::new(key.to_bytes());
        assert_eq!(key.public_key().as_bytes().len(), public_len);
        assert_eq!(encoded.len(), public_len + private_len + 9);
        println!("representacion,{scheme:?},{public_len},{private_len},{}", encoded.len());
    }
}

#[test]
fn retained_seed_recreates_signing_capability_after_key_drop() {
    for scheme in [SignatureScheme::Dilithium2, SignatureScheme::Dilithium3,
                   SignatureScheme::Dilithium5] {
        let retained_seed = Zeroizing::new([73; 32]);
        let public = {
            let original = DilithiumKeypair::from_seed(&retained_seed, scheme).unwrap();
            original.public_key().clone()
        };
        // La clave original ya salió de ámbito; conservar la semilla basta para firmar.
        let reconstructed = DilithiumKeypair::from_seed(&retained_seed, scheme).unwrap();
        assert_eq!(public.as_bytes(), reconstructed.public_key().as_bytes());
        let message = b"NEXUS TG2: operacion posterior a reconstruir desde semilla";
        let signature = reconstructed.sign(message).unwrap();
        assert!(public.verify(message, &signature).unwrap());
    }
}

#[test]
fn backend_object_sizes_differ_from_encoded_key_lengths() {
    use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
    use std::mem::size_of;
    fn zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    zeroizes_on_drop::<ml_dsa_44::PrivateKey>();
    zeroizes_on_drop::<ml_dsa_65::PrivateKey>();
    zeroizes_on_drop::<ml_dsa_87::PrivateKey>();
    // Layout de fips204 0.4.6: 128 bytes y L+2K polinomios de 256 i32.
    let sizes = [size_of::<ml_dsa_44::PrivateKey>(), size_of::<ml_dsa_65::PrivateKey>(),
                 size_of::<ml_dsa_87::PrivateKey>()];
    assert_eq!(sizes, [12416, 17536, 23680]);
    println!("objetos_backend,{},{},{}", sizes[0], sizes[1], sizes[2]);
    // size_of no contabiliza toda la pila, registros, copias ni residuos físicos.
}
