/*
 * Copyright 2026 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::discovery::ActivePivSession;
use crate::piv_key_slot::{PivObjectClass, PivObjectId, slot_to_ckaid};
use common::yk_dbg;
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use pkcs11_sys::*;
use x509_cert::Certificate;
use yubikit::keys::{MlDsaParameterSet, MlKemParameterSet, PublicKey};
use yubikit::piv::{ObjectId as PivSlotId, PinPolicy, PivError, Slot, TouchPolicy};
use yubikit::smartcard::{SmartCardError, Sw};

/// Yubico defined attributes
const YUBICO_BASE_VENDOR: u32 = 0x59554200;
const CKA_YUBICO: u32 = CKA_VENDOR_DEFINED + YUBICO_BASE_VENDOR;
pub(crate) const CKA_YUBICO_TOUCH_POLICY: u32 = CKA_YUBICO + 1;
pub(crate) const CKA_YUBICO_PIN_POLICY: u32 = CKA_YUBICO + 2;

/// The Yubico-private X.509 extension an attestation certificate
/// carries its origin slot's PIN/touch policy in.
const OID_USAGE_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.8");

#[derive(Clone)]
pub struct PivObject {
    pub id: PivObjectId,
    pub(crate) class: PivObjectClass,
    pub(crate) slot: Slot,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
    generated: bool,
    public_key: Option<PublicKey>,
    cert_der: Option<Vec<u8>>,
    subject_der: Option<Vec<u8>>,
    issuer_der: Option<Vec<u8>>,
    serial_der: Option<Vec<u8>>,
    ec_params_der: Option<Vec<u8>>,
    data: Option<Vec<u8>>,
}

impl PivObject {
    /// A minimal object with every optional field unset — a base for
    /// struct-update syntax at each call site that only overrides what's
    /// relevant to that object.
    fn new(id: PivObjectId, class: PivObjectClass, slot: Slot) -> Self {
        Self {
            id,
            class,
            slot,
            pin_policy: PinPolicy::Default,
            touch_policy: TouchPolicy::Default,
            generated: false,
            public_key: None,
            cert_der: None,
            subject_der: None,
            issuer_der: None,
            serial_der: None,
            ec_params_der: None,
            data: None,
        }
    }
}

/// Reads the PIN/touch policy an attestation certificate asserts for its key
fn parse_attestation(cert: &Certificate) -> Option<(PinPolicy, TouchPolicy)> {
    let ext = cert
        .tbs_certificate()
        .extensions()?
        .iter()
        .find(|ext| ext.extn_id == OID_USAGE_POLICY)?;

    let bytes = ext.extn_value.as_bytes();
    let pin_policy = PinPolicy::from_u8(*bytes.first()?)?;
    let touch_policy = TouchPolicy::from_u8(*bytes.get(1)?)?;

    Some((pin_policy, touch_policy))
}

/// Whether a slot's key, independent of whatever certificate it might also
/// hold, is known to exist, known to be absent, or genuinely undeterminable
/// since attestation only works for on-device generated keys and slot
/// metadata needs firmware >= 5.3).
enum KeyPresence {
    Present(PublicKey),
    Absent,
    Unknown,
}

fn is_key_absent(err: &PivError) -> bool {
    let PivError::Connection(SmartCardError::Apdu { sw, .. }) = err else {
        return false;
    };
    matches!(
        Sw::from_u16(*sw),
        Some(Sw::ReferenceDataNotFound | Sw::WrongParametersP1P2)
    )
}

/// Figures out whether `slot` actually has a key in it, independent of
/// whether it also has a certificate
/// Return (KeyPresence, PinPolicy, TouchPolicy, generated, Option<attestation cert>)
fn detect_key(
    piv: &mut ActivePivSession,
    slot: Slot,
) -> (KeyPresence, PinPolicy, TouchPolicy, bool, Option<Vec<u8>>) {
    match piv.attest_key(slot) {
        Ok(attestation_der) => {
            let mut pin_policy = PinPolicy::Default;
            let mut touch_policy = TouchPolicy::Default;
            if let Ok(attestation_cert) = Certificate::from_der(&attestation_der) {
                if let Some((pp, tp)) = parse_attestation(&attestation_cert) {
                    pin_policy = pp;
                    touch_policy = tp;
                }
                let public_key = attestation_cert
                    .tbs_certificate()
                    .subject_public_key_info()
                    .to_der()
                    .ok()
                    .and_then(|der| PublicKey::from_spki(&der).ok());
                if let Some(public_key) = public_key {
                    return (
                        KeyPresence::Present(public_key),
                        pin_policy,
                        touch_policy,
                        true,
                        Some(attestation_der),
                    );
                }
            }
            // A key exists (attestation succeeded) but we couldn't get a
            // usable public key out of it. Fall through and give metadata a shot.
        }
        Err(e) if is_key_absent(&e) => {
            return (
                KeyPresence::Absent,
                PinPolicy::Default,
                TouchPolicy::Default,
                false,
                None,
            );
        }
        Err(_) => {}
    }

    match piv.get_slot_metadata(slot) {
        Ok(metadata) => (
            KeyPresence::Present(metadata.public_key),
            metadata.pin_policy,
            metadata.touch_policy,
            metadata.generated,
            None,
        ),
        Err(e) if is_key_absent(&e) => (
            KeyPresence::Absent,
            PinPolicy::Default,
            TouchPolicy::Default,
            false,
            None,
        ),
        Err(_) => (
            KeyPresence::Unknown,
            PinPolicy::Default,
            TouchPolicy::Default,
            false,
            None,
        ),
    }
}

fn read_slot_objects(piv: &mut ActivePivSession, slot: Slot) -> Vec<PivObject> {
    let mut found = Vec::new();

    let (key_presence, pin_policy, touch_policy, generated, attestation_der) =
        detect_key(piv, slot);

    // The raw data object backing this container, same bytes CKO_DATA's
    // CKA_VALUE exposes. Independent of both the
    // key and the certificate below.
    if let Ok(raw) = piv.get_object(PivSlotId::from_slot(slot)) {
        let id = PivObjectId::from_slot_class(PivObjectClass::Data, slot);
        found.push(PivObject {
            pin_policy,
            touch_policy,
            generated,
            data: Some(raw),
            ..PivObject::new(id, PivObjectClass::Data, slot)
        });
    }

    let mut cert_public_key = None;
    let mut ec_params_der = None;
    if let Ok(cert_der) = piv.get_certificate(slot) {
        if let Ok(cert) = Certificate::from_der(&cert_der) {
            let tbs = cert.tbs_certificate();
            if let (Ok(subject_der), Ok(issuer_der), Ok(serial_der), Ok(spki_der)) = (
                tbs.subject().to_der(),
                tbs.issuer().to_der(),
                tbs.serial_number().to_der(),
                tbs.subject_public_key_info().to_der(),
            ) {
                if let Ok(pk) = PublicKey::from_spki(&spki_der) {
                    if matches!(
                        pk,
                        PublicKey::Rsa(_)
                            | PublicKey::Ec(_)
                            | PublicKey::Ed25519(_)
                            | PublicKey::X25519(_)
                            | PublicKey::MlDsa(_)
                            | PublicKey::MlKem(_)
                    ) {
                        if let PublicKey::Ec(_) = &pk {
                            ec_params_der = tbs
                                .subject_public_key_info()
                                .algorithm
                                .parameters
                                .as_ref()
                                .and_then(|p| p.to_der().ok());
                        }
                        cert_public_key = Some(pk);
                        let id = PivObjectId::from_slot_class(PivObjectClass::Certificate, slot);
                        found.push(PivObject {
                            pin_policy,
                            touch_policy,
                            generated,
                            cert_der: Some(cert_der),
                            subject_der: Some(subject_der),
                            issuer_der: Some(issuer_der),
                            serial_der: Some(serial_der),
                            ec_params_der: ec_params_der.clone(),
                            ..PivObject::new(id, PivObjectClass::Certificate, slot)
                        });
                    }
                }
            }
        }
    }

    if let Some(attestation_der) = attestation_der {
        // An attestation cert exposes the same CKA_SUBJECT/CKA_ISSUER/CKA_SERIAL_NUMBER
        // as a regular certificate object but is a freshly generated, not
        // token-persisted, certificate.
        let (subject_der, issuer_der, serial_der) = Certificate::from_der(&attestation_der)
            .ok()
            .map(|cert| {
                let tbs = cert.tbs_certificate();
                (
                    tbs.subject().to_der().ok(),
                    tbs.issuer().to_der().ok(),
                    tbs.serial_number().to_der().ok(),
                )
            })
            .unwrap_or((None, None, None));

        let id = PivObjectId::from_slot_class(PivObjectClass::AttestationCertificate, slot);
        found.push(PivObject {
            pin_policy,
            touch_policy,
            generated,
            cert_der: Some(attestation_der),
            subject_der,
            issuer_der,
            serial_der,
            ..PivObject::new(id, PivObjectClass::AttestationCertificate, slot)
        });
    }

    // Match the public key (if any) to this slot's key objects.
    // A confirmed device key always wins over the cert's
    // SPKI, even when they disagree.
    let key_public_key = match (&key_presence, &cert_public_key) {
        (KeyPresence::Present(pk), Some(cert_pk)) if pk != cert_pk => {
            log::warn!(
                "Slot {:?}: certificate's public key doesn't match the key \
                     reported by attestation/metadata -- exposing the device key",
                slot
            );
            Some(pk.clone())
        }
        (KeyPresence::Present(pk), _) => Some(pk.clone()),
        (KeyPresence::Absent, _) => None,

        // Undeterminable (old firmware + imported key). Fall back to
        // the cert's key as a heuristic.
        (KeyPresence::Unknown, cert_pk) => cert_pk.clone(),
    };

    if let Some(public_key) = key_public_key {
        for class in [PivObjectClass::PublicKey, PivObjectClass::PrivateKey] {
            let id = PivObjectId::from_slot_class(class, slot);
            found.push(PivObject {
                pin_policy,
                touch_policy,
                generated,
                public_key: Some(public_key.clone()),
                ec_params_der: ec_params_der.clone(),
                ..PivObject::new(id, class, slot)
            });
        }
    }

    found
}

pub fn read_objects(piv: &mut ActivePivSession) -> Vec<PivObject> {
    let mut found = Vec::new();
    for slot in Slot::key_slots().chain(std::iter::once(Slot::Attestation)) {
        found.extend(read_slot_objects(piv, slot));
    }

    // Non-per-slot generic data objects.
    // Unlike all other objects, these aren't tied to any
    // PIV key slot, so they're probed once per session rather than once
    // per slot.
    // They only ever produce a `Data`-class object, their
    // sub_ids never appear in find_cert_object/find_pvtk_object/
    // find_pubk_object's lookup tables
    if let Ok(raw) = piv.get_object(PivSlotId::Capability) {
        push_data_object(&mut found, PivObjectId::PIV_DATA_OBJ_CCC, raw);
    }
    if let Ok(raw) = piv.get_object(PivSlotId::Chuid) {
        push_data_object(&mut found, PivObjectId::PIV_DATA_OBJ_CHUI, raw);
    }
    if let Ok(raw) = piv.get_object(PivSlotId::Security) {
        push_data_object(&mut found, PivObjectId::PIV_DATA_OBJ_SEC_OBJ, raw);
    }
    if let Ok(raw) = piv.get_object(PivSlotId::Discovery) {
        push_data_object(&mut found, PivObjectId::PIV_DATA_OBJ_DISCOVERY, raw);
    }
    if let Ok(raw) = piv.get_object(PivSlotId::KeyHistory) {
        push_data_object(&mut found, PivObjectId::PIV_DATA_OBJ_HISTORY, raw);
    }
    // yubikit's ObjectId enum doesn't have these two (yet). Raw numeric
    // tags from ykpiv.h (YKPIV_OBJ_SM_SIGNER/YKPIV_OBJ_PC_REF_DATA).
    if let Ok(raw) = piv.get_object_raw(0x5fc122) {
        push_data_object(&mut found, PivObjectId::PIV_DATA_OBJ_SM_SIGNER, raw);
    }
    if let Ok(raw) = piv.get_object_raw(0x5fc123) {
        push_data_object(&mut found, PivObjectId::PIV_DATA_OBJ_PC_REF_DATA, raw);
    }

    found
}

/// Re-reads one slot's objects after, for example, `C_GenerateKeyPair`
pub(crate) fn refresh_slot_objects(
    objects: &mut Vec<PivObject>,
    piv: &mut ActivePivSession,
    slot: Slot,
) {
    let stale_ids = [
        PivObjectClass::Certificate,
        PivObjectClass::PublicKey,
        PivObjectClass::PrivateKey,
        PivObjectClass::Data,
        PivObjectClass::AttestationCertificate,
    ]
    .map(|class| PivObjectId::from_slot_class(class, slot));
    objects.retain(|o| !stale_ids.contains(&o.id));
    objects.extend(read_slot_objects(piv, slot));
}

fn push_data_object(found: &mut Vec<PivObject>, id: PivObjectId, raw: Vec<u8>) {
    found.push(PivObject {
        data: Some(raw),
        ..PivObject::new(id, PivObjectClass::Data, Slot::Authentication)
    });
}

/// Returns a list of handles of every object this slot currently exposes.
/// `include_private` should be `false` while the slot isn't logged in
pub fn object_handles(objects: &[PivObject], include_private: bool) -> Vec<CK_OBJECT_HANDLE> {
    objects
        .iter()
        .filter(|o| include_private || o.class != PivObjectClass::PrivateKey)
        .map(|o| o.id as CK_OBJECT_HANDLE)
        .collect()
}

fn find_object(objects: &[PivObject], handle: CK_OBJECT_HANDLE) -> Option<&PivObject> {
    objects.iter().find(|o| o.id as CK_OBJECT_HANDLE == handle)
}

fn find_key(
    objects: &[PivObject],
    handle: CK_OBJECT_HANDLE,
    class: PivObjectClass,
) -> Option<(Slot, &PublicKey)> {
    let obj = find_object(objects, handle)?;
    if obj.class != class {
        return None;
    }
    Some((obj.slot, obj.public_key.as_ref()?))
}

pub fn find_private_key(
    objects: &[PivObject],
    handle: CK_OBJECT_HANDLE,
) -> Option<(Slot, &PublicKey)> {
    find_key(objects, handle, PivObjectClass::PrivateKey)
}

pub fn find_public_key(
    objects: &[PivObject],
    handle: CK_OBJECT_HANDLE,
) -> Option<(Slot, &PublicKey)> {
    find_key(objects, handle, PivObjectClass::PublicKey)
}

pub fn get_attribute(
    objects: &[PivObject],
    handle: CK_OBJECT_HANDLE,
    attr_type: CK_ATTRIBUTE_TYPE,
) -> Option<Vec<u8>> {
    let obj = find_object(objects, handle)?;
    match obj.class {
        PivObjectClass::Certificate => get_cert_attribute(obj, attr_type, true),
        PivObjectClass::PublicKey => get_pubkey_attribute(obj, attr_type),
        PivObjectClass::PrivateKey => get_privkey_attribute(obj, attr_type),
        PivObjectClass::Data => get_data_attribute(obj, attr_type),
        PivObjectClass::AttestationCertificate => get_cert_attribute(obj, attr_type, false),
        PivObjectClass::SecretKey => get_secret_key_attribute(obj, attr_type),
    }
}

/// Returns the attributes of the ECDH shared secret `C_DeriveKey` produces.
/// It is extractable, with its raw bytes in `CKA_VALUE`.
fn get_secret_key_attribute(obj: &PivObject, attr_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
    yk_dbg!("For secret key object {}, get ", obj.id as CK_OBJECT_HANDLE);
    match attr_type as u32 {
        CKA_CLASS => {
            yk_dbg!("CLASS");
            Some(cka_ulong(CKO_SECRET_KEY))
        }
        CKA_KEY_TYPE => {
            yk_dbg!("KEY_TYPE");
            Some(cka_ulong(CKK_GENERIC_SECRET))
        }
        CKA_TOKEN => {
            yk_dbg!("TOKEN");
            Some(cka_bool(false))
        }
        CKA_PRIVATE => {
            yk_dbg!("PRIVATE");
            Some(cka_bool(true))
        }
        CKA_LOCAL => {
            yk_dbg!("LOCAL");
            Some(cka_bool(false))
        }
        CKA_SENSITIVE
        | CKA_ALWAYS_SENSITIVE
        | CKA_NEVER_EXTRACTABLE
        | CKA_ENCRYPT
        | CKA_DECRYPT
        | CKA_DERIVE
        | CKA_MODIFIABLE => {
            yk_dbg!("{:x}", attr_type);
            Some(cka_bool(false))
        }
        CKA_EXTRACTABLE => {
            yk_dbg!("EXTRACTABLE");
            Some(cka_bool(true))
        }
        CKA_LABEL => {
            yk_dbg!("LABEL");
            Some(obj.id.label().as_bytes().to_vec())
        }
        CKA_ID => {
            yk_dbg!("ID");
            Some(vec![0])
        }
        CKA_VALUE => {
            yk_dbg!("VALUE");
            obj.data.clone()
        }
        _ => {
            yk_dbg!("UNKNOWN ATTRIBUTE {:x} ({})", attr_type, attr_type);
            None
        }
    }
}

/// Builds (or replaces) the single `PIV_SECRET_OBJ` object with a freshly
/// derived ECDH shared secret.
pub(crate) fn store_secret_key(objects: &mut Vec<PivObject>, slot: Slot, secret: Vec<u8>) {
    objects.retain(|o| o.class != PivObjectClass::SecretKey);
    objects.push(PivObject {
        data: Some(secret),
        ..PivObject::new(PivObjectId::PIV_SECRET_OBJ, PivObjectClass::SecretKey, slot)
    });
}

fn cka_bool(b: bool) -> Vec<u8> {
    vec![b as u8]
}

// Takes a plain u32 since every caller passes either a bindgen CKx constant
// (always u32, regardless of CK_ULONG's platform-dependent width) or a
// small derived value. Returns the full native CK_ULONG width/encoding.
fn cka_ulong(v: u32) -> Vec<u8> {
    (v as CK_ULONG).to_ne_bytes().to_vec()
}

fn key_type_attr(key: &PublicKey) -> Option<Vec<u8>> {
    let kt = match key {
        PublicKey::Rsa(_) => CKK_RSA,
        PublicKey::Ec(_) => CKK_EC,
        PublicKey::Ed25519(_) => CKK_EC_EDWARDS,
        PublicKey::X25519(_) => CKK_EC_MONTGOMERY,
        PublicKey::MlDsa(_) => CKK_ML_DSA,
        PublicKey::MlKem(_) => CKK_ML_KEM,
        _ => return None,
    };
    Some(cka_ulong(kt))
}

/// The ML-DSA/ML-KEM analogue of `CKA_EC_PARAMS`
fn parameter_set_attr(key: &PublicKey) -> Option<Vec<u8>> {
    match key {
        PublicKey::MlDsa(k) => Some(cka_ulong(match k.parameter_set {
            MlDsaParameterSet::MlDsa44 => CKP_ML_DSA_44,
            MlDsaParameterSet::MlDsa65 => CKP_ML_DSA_65,
            MlDsaParameterSet::MlDsa87 => CKP_ML_DSA_87,
            _ => return None,
        })),
        PublicKey::MlKem(k) => Some(cka_ulong(match k.parameter_set {
            MlKemParameterSet::MlKem512 => CKP_ML_KEM_512,
            MlKemParameterSet::MlKem768 => CKP_ML_KEM_768,
            MlKemParameterSet::MlKem1024 => CKP_ML_KEM_1024,
            _ => return None,
        })),
        _ => None,
    }
}

/// `CKA_VALUE` for an ML-DSA or ML-KEM public key object — the raw public
/// key bytes
fn raw_key_value_attr(key: &PublicKey) -> Option<Vec<u8>> {
    match key {
        PublicKey::MlDsa(k) => Some(k.key.clone()),
        PublicKey::MlKem(k) => Some(k.key.clone()),
        _ => None,
    }
}

/// `CKA_EC_PARAMS` for Ed25519/X25519 keys isn't a real OID. yubico-piv-tool
/// encodes it as a PrintableString naming the curve instead (objects.c:42-43),
/// since RFC 8410 SPKI for these algorithms carries no AlgorithmIdentifier
/// parameters to derive it from the certificate.
pub(crate) const ED25519_CURVE_PARAMS: &[u8] = &[
    0x13, 0x0c, b'e', b'd', b'w', b'a', b'r', b'd', b's', b'2', b'5', b'5', b'1', b'9',
];
pub(crate) const X25519_CURVE_PARAMS: &[u8] = &[
    0x13, 0x0b, b'c', b'u', b'r', b'v', b'e', b'2', b'5', b'5', b'1', b'9',
];

fn ec_params_attr(obj: &PivObject, public_key: &PublicKey) -> Option<Vec<u8>> {
    match public_key {
        PublicKey::Ed25519(_) => Some(ED25519_CURVE_PARAMS.to_vec()),
        PublicKey::X25519(_) => Some(X25519_CURVE_PARAMS.to_vec()),
        PublicKey::Ec(_) => obj.ec_params_der.clone(),
        _ => None,
    }
}

/// `CKA_EC_POINT` content for any point-shaped key. SEC1 uncompressed
/// bytes for NIST/Brainpool EC, or the raw 32-byte key for Ed25519/X25519
fn ec_point_bytes(public_key: &PublicKey) -> Option<Vec<u8>> {
    match public_key {
        PublicKey::Ec(k) => ec_point_attr(&k.point),
        PublicKey::Ed25519(k) => ec_point_attr(&k.key),
        PublicKey::X25519(k) => ec_point_attr(&k.key),
        _ => None,
    }
}

/// `CKA_EC_POINT` is the DER encoding of an OCTET STRING wrapping the raw
/// SEC1 point, not the raw point bytes themselves
fn ec_point_attr(point: &[u8]) -> Option<Vec<u8>> {
    der::asn1::OctetStringRef::new(point).ok()?.to_der().ok()
}

fn get_cert_attribute(
    obj: &PivObject,
    attr_type: CK_ATTRIBUTE_TYPE,
    token: bool,
) -> Option<Vec<u8>> {
    yk_dbg!(
        "For certificate object {}, get ",
        obj.id as CK_OBJECT_HANDLE
    );
    match attr_type as u32 {
        CKA_CLASS => {
            yk_dbg!("CLASS");
            Some(cka_ulong(CKO_CERTIFICATE))
        }
        CKA_TOKEN => {
            yk_dbg!("TOKEN");
            Some(cka_bool(token))
        }
        CKA_PRIVATE => {
            yk_dbg!("PRIVATE");
            Some(cka_bool(false))
        }
        CKA_LABEL => {
            yk_dbg!("LABEL");
            Some(obj.id.label().as_bytes().to_vec())
        }
        CKA_SUBJECT => {
            yk_dbg!("SUBJECT");
            obj.subject_der.clone()
        }
        CKA_ISSUER => {
            yk_dbg!("ISSUER");
            obj.issuer_der.clone()
        }
        CKA_SERIAL_NUMBER => {
            yk_dbg!("SERIAL_NUMBER");
            obj.serial_der.clone()
        }
        CKA_VALUE => {
            yk_dbg!("VALUE");
            obj.cert_der.clone()
        }
        CKA_CERTIFICATE_TYPE => {
            yk_dbg!("CERTIFICATE TYPE");
            Some(cka_ulong(CKC_X_509))
        }
        CKA_ID => {
            yk_dbg!("ID");
            Some(vec![slot_to_ckaid(obj.slot)])
        }
        CKA_MODIFIABLE => {
            yk_dbg!("MODIFIABLE");
            Some(cka_bool(false))
        }
        CKA_COPYABLE => {
            yk_dbg!("COPYABLE");
            Some(cka_bool(false))
        }
        CKA_DESTROYABLE => {
            yk_dbg!("DESTROYABLE");
            Some(cka_bool(true))
        }
        CKA_TRUSTED => {
            yk_dbg!("TRUSTED");
            Some(cka_bool(false))
        }
        _ => {
            yk_dbg!("UNKNOWN ATTRIBUTE {:x} ({})", attr_type, attr_type);
            None
        }
    }
}

fn get_pubkey_attribute(obj: &PivObject, attr_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
    let public_key = obj.public_key.as_ref()?;
    yk_dbg!("For public key object {}, get ", obj.id as CK_OBJECT_HANDLE);
    match attr_type as u32 {
        CKA_CLASS => {
            yk_dbg!("CLASS");
            Some(cka_ulong(CKO_PUBLIC_KEY))
        }
        CKA_TOKEN => {
            yk_dbg!("TOKEN");
            Some(cka_bool(true))
        }
        CKA_ALWAYS_AUTHENTICATE => {
            yk_dbg!("ALWAYS_AUTHENTICATE");
            Some(cka_bool(false))
        }
        CKA_PRIVATE => {
            yk_dbg!("PRIVATE");
            Some(cka_bool(false))
        }
        CKA_SENSITIVE => {
            yk_dbg!("SENSITIVE");
            Some(cka_bool(false))
        }
        CKA_ALWAYS_SENSITIVE => {
            yk_dbg!("ALWAYS_SENSITIVE");
            Some(cka_bool(false))
        }
        CKA_EXTRACTABLE => {
            yk_dbg!("EXTRACTABLE");
            Some(cka_bool(true))
        }
        CKA_NEVER_EXTRACTABLE => {
            yk_dbg!("NEVER_EXTRACTABLE");
            Some(cka_bool(false))
        }
        CKA_COPYABLE => {
            yk_dbg!("COPYABLE");
            Some(cka_bool(false))
        }
        CKA_DESTROYABLE => {
            yk_dbg!("DESTROYABLE");
            Some(cka_bool(true))
        }
        CKA_LABEL => {
            yk_dbg!("LABEL");
            Some(obj.id.label().as_bytes().to_vec())
        }
        CKA_KEY_TYPE => {
            yk_dbg!("KEY TYPE");
            key_type_attr(public_key)
        }
        CKA_ID => {
            yk_dbg!("ID");
            Some(vec![slot_to_ckaid(obj.slot)])
        }
        CKA_TRUSTED => {
            yk_dbg!("TRUSTED");
            Some(cka_bool(false))
        }
        CKA_LOCAL => {
            yk_dbg!("LOCAL");
            Some(cka_bool(obj.generated))
        }
        CKA_ENCRYPT => {
            yk_dbg!("ENCRYPT");
            Some(cka_bool(true)) //Some(cka_bool(matches!(public_key, PublicKey::Rsa(_)))),
        }
        CKA_DECRYPT => {
            yk_dbg!("DECRYPT");
            Some(cka_bool(false))
        }
        CKA_SIGN => {
            yk_dbg!("SIGN");
            Some(cka_bool(false))
        }
        CKA_SIGN_RECOVER => {
            yk_dbg!("SIGN_RECOVER");
            Some(cka_bool(false))
        }
        CKA_VERIFY => {
            yk_dbg!("VERIFY");
            Some(cka_bool(true))
        }
        CKA_VERIFY_RECOVER => {
            yk_dbg!("VERIFY_RECOVER");
            Some(cka_bool(false))
        }
        CKA_WRAP => {
            yk_dbg!("WRAP");
            Some(cka_bool(false))
        }
        CKA_WRAP_WITH_TRUSTED => {
            yk_dbg!("WRAP_WITH_TRUSTED");
            Some(cka_bool(false))
        }
        CKA_UNWRAP => {
            yk_dbg!("UNWRAP");
            Some(cka_bool(false))
        }
        CKA_DERIVE => {
            yk_dbg!("DERIVE");
            Some(cka_bool(matches!(
                public_key,
                PublicKey::Ec(_) | PublicKey::X25519(_)
            )))
        }
        CKA_ENCAPSULATE => {
            yk_dbg!("ENCAPSULATE");
            Some(cka_bool(matches!(public_key, PublicKey::MlKem(_))))
        }
        CKA_EC_POINT => {
            yk_dbg!("EC_POINT");
            ec_point_bytes(public_key)
        }
        CKA_EC_PARAMS => {
            yk_dbg!("EC_PARAMS");
            ec_params_attr(obj, public_key)
        }
        CKA_MODULUS => {
            yk_dbg!("MODULUS");
            match public_key {
                PublicKey::Rsa(k) => Some(k.n.clone()),
                _ => None,
            }
        }
        CKA_MODULUS_BITS => {
            yk_dbg!("MODULUS BITS");
            match public_key {
                PublicKey::Rsa(k) => Some(cka_ulong(k.key_size.bit_len() as u32)),
                _ => None,
            }
        }
        CKA_PUBLIC_EXPONENT => {
            yk_dbg!("PUBLIC EXPONENT");
            match public_key {
                PublicKey::Rsa(k) => Some(k.e.clone()),
                _ => None,
            }
        }
        CKA_PARAMETER_SET => {
            yk_dbg!("PARAMETER_SET");
            parameter_set_attr(public_key)
        }
        CKA_VALUE => {
            yk_dbg!("VALUE");
            raw_key_value_attr(public_key)
        }
        CKA_MODIFIABLE => {
            yk_dbg!("MODIFIABLE");
            Some(cka_bool(false))
        }
        _ => {
            yk_dbg!("UNKNOWN ATTRIBUTE {:x} ({})", attr_type, attr_type);
            None
        }
    }
}

fn get_privkey_attribute(obj: &PivObject, attr_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
    let public_key = obj.public_key.as_ref()?;
    yk_dbg!(
        "For private key object {}, get ",
        obj.id as CK_OBJECT_HANDLE
    );
    match attr_type as u32 {
        CKA_CLASS => {
            yk_dbg!("CLASS");
            Some(cka_ulong(CKO_PRIVATE_KEY))
        }
        CKA_TOKEN => {
            yk_dbg!("TOKEN");
            Some(cka_bool(true))
        }
        CKA_PRIVATE => {
            yk_dbg!("PRIVATE");
            Some(cka_bool(true))
        }
        CKA_LABEL => {
            yk_dbg!("LABEL");
            Some(obj.id.label().as_bytes().to_vec())
        }
        CKA_KEY_TYPE => {
            yk_dbg!("KEY TYPE");
            key_type_attr(public_key)
        }
        CKA_ID => {
            yk_dbg!("ID");
            Some(vec![slot_to_ckaid(obj.slot)])
        }
        CKA_SENSITIVE => {
            yk_dbg!("SENSITIVE");
            Some(cka_bool(true))
        }
        CKA_ALWAYS_SENSITIVE => {
            yk_dbg!("ALWAYS_SENSITIVE");
            Some(cka_bool(true))
        }
        CKA_EXTRACTABLE => {
            yk_dbg!("EXTRACTABLE");
            Some(cka_bool(false))
        }
        CKA_COPYABLE => {
            yk_dbg!("COPYABLE");
            Some(cka_bool(false))
        }
        CKA_DESTROYABLE => {
            yk_dbg!("DESTROYABLE");
            Some(cka_bool(true))
        }
        CKA_NEVER_EXTRACTABLE => {
            yk_dbg!("NEVER_EXTRACTABLE");
            Some(cka_bool(true))
        }
        CKA_LOCAL => {
            yk_dbg!("LOCAL");
            Some(cka_bool(obj.generated))
        }
        CKA_ENCRYPT => {
            yk_dbg!("ENCRYPT");
            Some(cka_bool(false))
        }
        CKA_DECRYPT => {
            yk_dbg!("DECRYPT");
            // The attestation key cannot decrypt, sign, or do anything besides existing.
            Some(cka_bool(obj.slot != Slot::Attestation))
        }
        CKA_WRAP => {
            yk_dbg!("WRAP");
            Some(cka_bool(false))
        }
        CKA_WRAP_WITH_TRUSTED => {
            yk_dbg!("WRAP_WITH_TRUSTED");
            Some(cka_bool(false))
        }
        CKA_UNWRAP => {
            yk_dbg!("UNWRAP");
            Some(cka_bool(false))
        }
        CKA_SIGN => {
            yk_dbg!("SIGN");
            Some(cka_bool(obj.slot != Slot::Attestation))
        }
        CKA_VERIFY => {
            yk_dbg!("VERIFY");
            Some(cka_bool(false))
        }
        CKA_VERIFY_RECOVER => {
            yk_dbg!("VERIFY_RECOVER");
            Some(cka_bool(false))
        }
        CKA_DERIVE => {
            yk_dbg!("DERIVE");
            Some(cka_bool(false))
        }
        CKA_DECAPSULATE => {
            yk_dbg!("DECAPSULATE");
            Some(cka_bool(
                obj.slot != Slot::Attestation && matches!(public_key, PublicKey::MlKem(_)),
            ))
        }
        CKA_MODULUS => {
            yk_dbg!("MODULUS");
            match public_key {
                PublicKey::Rsa(k) => Some(k.n.clone()),
                _ => None,
            }
        }
        CKA_EC_POINT => {
            yk_dbg!("EC_POINT");
            ec_point_bytes(public_key)
        }
        CKA_EC_PARAMS => {
            yk_dbg!("EC_PARAMS");
            ec_params_attr(obj, public_key)
        }
        CKA_MODULUS_BITS => {
            yk_dbg!("MODULUS BITS");
            match public_key {
                PublicKey::Rsa(k) => Some(cka_ulong(k.key_size.bit_len() as u32)),
                _ => None,
            }
        }
        CKA_PUBLIC_EXPONENT => {
            yk_dbg!("PUBLIC EXPONENT");
            match public_key {
                PublicKey::Rsa(k) => Some(k.e.clone()),
                _ => None,
            }
        }
        CKA_PARAMETER_SET => {
            yk_dbg!("PARAMETER_SET");
            parameter_set_attr(public_key)
        }
        CKA_ALWAYS_AUTHENTICATE => {
            yk_dbg!("ALWAYS AUTHENTICATE");
            match obj.pin_policy {
                PinPolicy::Always => Some(cka_bool(true)),
                PinPolicy::Once | PinPolicy::Never => Some(cka_bool(false)),
                _ => match obj.slot {
                    Slot::Signature => Some(cka_bool(true)),
                    _ => Some(cka_bool(false)),
                },
            }
        }
        CKA_MODIFIABLE => {
            yk_dbg!("MODIFIABLE");
            Some(cka_bool(false))
        }
        CKA_SIGN_RECOVER => {
            yk_dbg!("SIGN_RECOVER");
            Some(cka_bool(false))
        }
        CKA_YUBICO_TOUCH_POLICY => {
            yk_dbg!("TOUCH POLICY");
            Some(vec![obj.touch_policy as u8])
        }
        CKA_YUBICO_PIN_POLICY => {
            yk_dbg!("PIN POLICY");
            Some(vec![obj.pin_policy as u8])
        }
        _ => {
            yk_dbg!("UNKNOWN ATTRIBUTE {:x} ({})", attr_type, attr_type);
            None
        }
    }
}

/// The PIV-spec object identifier (NIST SP 800-73) for a standard data
/// object's container, as raw DER content octets (no tag/length header)
fn data_object_oid(id: PivObjectId) -> Option<&'static [u8]> {
    match id {
        // 2.16.840.1.101.3.7.2.1.1
        PivObjectId::PIV_DATA_OBJ_X509_PIV_AUTH => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x01, 0x01])
        }
        // 2.16.840.1.101.3.7.2.1.0
        PivObjectId::PIV_DATA_OBJ_X509_DS => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x01, 0x00])
        }
        // 2.16.840.1.101.3.7.2.1.2
        PivObjectId::PIV_DATA_OBJ_X509_KM => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x01, 0x02])
        }
        // 2.16.840.1.101.3.7.2.5.0
        PivObjectId::PIV_DATA_OBJ_X509_CARD_AUTH => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x05, 0x00])
        }
        // 2.16.840.1.101.3.7.2.16.1
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED1 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x01])
        }
        // 2.16.840.1.101.3.7.2.16.2
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED2 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x02])
        }
        // 2.16.840.1.101.3.7.2.16.3
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED3 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x03])
        }
        // 2.16.840.1.101.3.7.2.16.4
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED4 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x04])
        }
        // 2.16.840.1.101.3.7.2.16.5
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED5 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x05])
        }
        // 2.16.840.1.101.3.7.2.16.6
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED6 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x06])
        }
        // 2.16.840.1.101.3.7.2.16.7
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED7 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x07])
        }
        // 2.16.840.1.101.3.7.2.16.8
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED8 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x08])
        }
        // 2.16.840.1.101.3.7.2.16.9
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED9 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x09])
        }
        // 2.16.840.1.101.3.7.2.16.10
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED10 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x0a])
        }
        // 2.16.840.1.101.3.7.2.16.11
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED11 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x0b])
        }
        // 2.16.840.1.101.3.7.2.16.12
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED12 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x0c])
        }
        // 2.16.840.1.101.3.7.2.16.13
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED13 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x0d])
        }
        // 2.16.840.1.101.3.7.2.16.14
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED14 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x0e])
        }
        // 2.16.840.1.101.3.7.2.16.15
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED15 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x0f])
        }
        // 2.16.840.1.101.3.7.2.16.16
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED16 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x10])
        }
        // 2.16.840.1.101.3.7.2.16.17
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED17 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x11])
        }
        // 2.16.840.1.101.3.7.2.16.18
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED18 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x12])
        }
        // 2.16.840.1.101.3.7.2.16.19
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED19 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x13])
        }
        // 2.16.840.1.101.3.7.2.16.20
        PivObjectId::PIV_DATA_OBJ_X509_RETIRED20 => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x14])
        }
        // 1.3.6.1.4.1.41482.3
        PivObjectId::PIV_DATA_OBJ_X509_ATTESTATION => {
            Some(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xc4, 0x0a, 0x03])
        }
        // 2.16.840.1.101.3.7.1.219.0
        PivObjectId::PIV_DATA_OBJ_CCC => Some(&[
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x01, 0x81, 0x5b, 0x00,
        ]),
        // 2.16.840.1.101.3.7.2.48.0
        PivObjectId::PIV_DATA_OBJ_CHUI => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x30, 0x00])
        }
        // 2.16.840.1.101.3.7.2.144.0
        PivObjectId::PIV_DATA_OBJ_SEC_OBJ => Some(&[
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x81, 0x10, 0x00,
        ]),
        // 2.16.840.1.101.3.7.2.96.80
        PivObjectId::PIV_DATA_OBJ_DISCOVERY => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x60, 0x50])
        }
        // 2.16.840.1.101.3.7.2.96.96
        PivObjectId::PIV_DATA_OBJ_HISTORY => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x60, 0x60])
        }
        // 2.16.840.1.101.3.7.2.16.23
        PivObjectId::PIV_DATA_OBJ_SM_SIGNER => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x17])
        }
        // 2.16.840.1.101.3.7.2.16.24
        PivObjectId::PIV_DATA_OBJ_PC_REF_DATA => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x10, 0x18])
        }
        _ => None,
    }
}

fn get_data_attribute(obj: &PivObject, attr_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
    yk_dbg!("For data object {}, get ", obj.id as CK_OBJECT_HANDLE);
    match attr_type as u32 {
        CKA_CLASS => {
            yk_dbg!("CLASS");
            Some(cka_ulong(CKO_DATA))
        }
        CKA_TOKEN => {
            yk_dbg!("TOKEN");
            Some(cka_bool(true))
        }
        CKA_PRIVATE => {
            yk_dbg!("PRIVATE");
            Some(cka_bool(false))
        }
        CKA_LABEL => {
            yk_dbg!("LABEL");
            Some(obj.id.label().as_bytes().to_vec())
        }
        CKA_ID => {
            yk_dbg!("ID");
            let cka_id = match obj.id {
                PivObjectId::PIV_DATA_OBJ_CCC => 26,
                PivObjectId::PIV_DATA_OBJ_CHUI => 27,
                PivObjectId::PIV_DATA_OBJ_SEC_OBJ => 29,
                PivObjectId::PIV_DATA_OBJ_DISCOVERY => 32,
                PivObjectId::PIV_DATA_OBJ_HISTORY => 33,
                PivObjectId::PIV_DATA_OBJ_SM_SIGNER => 36,
                PivObjectId::PIV_DATA_OBJ_PC_REF_DATA => 37,
                _ => slot_to_ckaid(obj.slot),
            };
            Some(vec![cka_id])
        }
        CKA_APPLICATION => {
            yk_dbg!("APPLICATION");
            Some(obj.id.label().as_bytes().to_vec())
        }
        CKA_OBJECT_ID => {
            yk_dbg!("OID");
            data_object_oid(obj.id).map(|oid| oid.to_vec())
        }
        CKA_MODIFIABLE => {
            yk_dbg!("MODIFIABLE");
            Some(cka_bool(false))
        }
        CKA_VALUE => {
            yk_dbg!("VALUE");
            obj.data.clone()
        }
        CKA_COPYABLE => {
            yk_dbg!("COPYABLE");
            Some(cka_bool(false))
        }
        CKA_DESTROYABLE => {
            yk_dbg!("DESTROYABLE");
            Some(cka_bool(true))
        }
        _ => {
            yk_dbg!("UNKNOWN ATTRIBUTE {:x} ({})", attr_type, attr_type);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::PivBackend;
    use crate::pkcs11_slot::Pkcs11SlotData;
    use common::backend::Slot as EngineSlot;
    use common::session::LoginState;

    fn test_object(id: PivObjectId, class: PivObjectClass, slot: Slot) -> PivObject {
        PivObject::new(id, class, slot)
    }

    fn test_slot(objects: Vec<PivObject>, login_state: LoginState) -> EngineSlot<PivBackend> {
        let mut data = Pkcs11SlotData::new("test reader".to_string());
        data.objects = objects;
        EngineSlot {
            login_state,
            sessions: std::collections::HashMap::new(),
            data,
        }
    }

    #[test]
    fn destroy_object_rejects_an_unknown_handle() {
        let mut slot = test_slot(Vec::new(), LoginState::SO);
        assert_eq!(
            crate::destroy_object::destroy_object(&mut slot, 1, 999),
            Err(CKR_OBJECT_HANDLE_INVALID.into())
        );
    }

    #[test]
    fn destroy_object_removes_the_secret_key_singleton_without_login() {
        let obj = test_object(
            PivObjectId::PIV_SECRET_OBJ,
            PivObjectClass::SecretKey,
            Slot::Authentication,
        );
        let mut slot = test_slot(vec![obj], LoginState::Public);
        assert_eq!(
            crate::destroy_object::destroy_object(
                &mut slot,
                1,
                PivObjectId::PIV_SECRET_OBJ as CK_OBJECT_HANDLE
            ),
            Ok(())
        );
        assert!(slot.data.objects.is_empty());
    }

    #[test]
    fn destroy_object_requires_so_login_for_a_private_key_handle() {
        let obj = test_object(
            PivObjectId::PIV_PVTK_OBJ_PIV_AUTH,
            PivObjectClass::PrivateKey,
            Slot::Authentication,
        );
        let handle = obj.id as CK_OBJECT_HANDLE;
        let mut slot = test_slot(vec![obj], LoginState::User);
        assert_eq!(
            crate::destroy_object::destroy_object(&mut slot, 1, handle),
            Err(CKR_USER_TYPE_INVALID.into())
        );
    }

    #[test]
    fn destroy_object_treats_a_private_key_handle_like_its_slots_certificate() {
        let obj = test_object(
            PivObjectId::PIV_PVTK_OBJ_PIV_AUTH,
            PivObjectClass::PrivateKey,
            Slot::Authentication,
        );
        let handle = obj.id as CK_OBJECT_HANDLE;
        let mut slot = test_slot(vec![obj], LoginState::SO);
        assert_eq!(
            crate::destroy_object::destroy_object(&mut slot, 1, handle),
            Err(CKR_TOKEN_NOT_PRESENT.into())
        );
    }

    #[test]
    fn destroy_object_rejects_a_data_object_as_a_deliberate_scope_limit() {
        let obj = test_object(
            PivObjectId::PIV_DATA_OBJ_CHUI,
            PivObjectClass::Data,
            Slot::Authentication,
        );
        let handle = obj.id as CK_OBJECT_HANDLE;
        let mut slot = test_slot(vec![obj], LoginState::SO);
        assert_eq!(
            crate::destroy_object::destroy_object(&mut slot, 1, handle),
            Err(CKR_ACTION_PROHIBITED.into())
        );
    }

    #[test]
    fn destroy_object_requires_so_login_for_a_certificate_handle() {
        let obj = test_object(
            PivObjectId::PIV_CERT_OBJ_X509_PIV_AUTH,
            PivObjectClass::Certificate,
            Slot::Authentication,
        );
        let handle = obj.id as CK_OBJECT_HANDLE;
        let mut slot = test_slot(vec![obj], LoginState::User);
        assert_eq!(
            crate::destroy_object::destroy_object(&mut slot, 1, handle),
            Err(CKR_USER_TYPE_INVALID.into())
        );
    }
}
