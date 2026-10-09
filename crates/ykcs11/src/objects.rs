// Copyright 2026 Yubico AB
// Licensed under the BSD 2-Clause License

//! PKCS#11 object model for PIV certificates/keys, matching ykcs11.c's
//! object.c/objects.c model across all 25 PIV slots: the 4 standard
//! containers (9a/9c/9d/9e), the 20 retired key-management slots (82-95),
//! and the dynamically-generated attestation certificate (f9). RSA, EC
//! (NIST/Brainpool), Ed25519, and X25519 keys are modeled; post-quantum
//! (ML-DSA/ML-KEM) PIV keys are a known gap to close later. Also modeled:
//! the 7 non-per-slot generic data objects the C reference itself discovers
//! (CCC, CHUID, Security Object, Discovery Object, Key History Object, SM
//! Signer, Pairing Code Reference Data — `token_objects[]`, token.c:107-118)
//! — the other 6 (fingerprints, facial images, printed information, iris
//! images, BITGT) aren't modeled since the C reference doesn't discover
//! them either (commented out of `token_objects[]`, needing biometric/extra
//! auth handling this module doesn't implement).
//!
//! Each container can independently hold a certificate and/or a key (the two
//! aren't guaranteed to be in sync — a cert can be imported with no matching
//! key, a key can exist with no cert ever loaded, or a regenerated key can
//! leave a stale, non-matching cert behind), so discovery treats "does this
//! slot have a cert" and "does this slot have a key" as separate questions
//! and reconciles them explicitly rather than assuming one implies the
//! other.

use crate::discovery::ActivePivSession;
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use pkcs11_common::yk_dbg;
use pkcs11_sys::*;
use x509_cert::Certificate;
use yubikit::keys::PublicKey;
use yubikit::piv::{ObjectId, PinPolicy, PivError, Slot, TouchPolicy};
use yubikit::smartcard::{SmartCardError, Sw};

/// Yubico defined attributes
const YUBICO_BASE_VENDOR: u32 = 0x59554200;
const CKA_YUBICO: u32 = CKA_VENDOR_DEFINED + YUBICO_BASE_VENDOR;
const CKA_YUBICO_TOUCH_POLICY: u32 = CKA_YUBICO + 1;
const CKA_YUBICO_PIN_POLICY: u32 = CKA_YUBICO + 2;


/// YKPIV_OID_USAGE_POLICY (ykpiv.h:808) — the Yubico-private X.509 extension
/// an attestation certificate carries its origin slot's PIN/touch policy in.
const OID_USAGE_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.8");

const ALL_SLOTS: [Slot; 25] = [
    Slot::Authentication,
    Slot::Signature,
    Slot::KeyManagement,
    Slot::CardAuth,
    Slot::Retired1,
    Slot::Retired2,
    Slot::Retired3,
    Slot::Retired4,
    Slot::Retired5,
    Slot::Retired6,
    Slot::Retired7,
    Slot::Retired8,
    Slot::Retired9,
    Slot::Retired10,
    Slot::Retired11,
    Slot::Retired12,
    Slot::Retired13,
    Slot::Retired14,
    Slot::Retired15,
    Slot::Retired16,
    Slot::Retired17,
    Slot::Retired18,
    Slot::Retired19,
    Slot::Retired20,
    Slot::Attestation,
];

/// `CKA_ID` for every object derived from this container — matches the
/// PKCS#11 "slot" numbering in ykcs11's own docs (1-4 for 9a/9c/9d/9e).
fn slot_cka_id(slot: Slot) -> u8 {
    match slot {
        Slot::Authentication => 1,
        Slot::Signature => 2,
        Slot::KeyManagement => 3,
        Slot::CardAuth => 4,
        Slot::Retired1 => 5,
        Slot::Retired2 => 6,
        Slot::Retired3 => 7,
        Slot::Retired4 => 8,
        Slot::Retired5 => 9,
        Slot::Retired6 => 10,
        Slot::Retired7 => 11,
        Slot::Retired8 => 12,
        Slot::Retired9 => 13,
        Slot::Retired10 => 14,
        Slot::Retired11 => 15,
        Slot::Retired12 => 16,
        Slot::Retired13 => 17,
        Slot::Retired14 => 18,
        Slot::Retired15 => 19,
        Slot::Retired16 => 20,
        Slot::Retired17 => 21,
        Slot::Retired18 => 22,
        Slot::Retired19 => 23,
        Slot::Retired20 => 24,
        Slot::Attestation => 25,
        // yubikit::piv::Slot is #[non_exhaustive] — every slot that exists
        // today is covered above, this only guards future additions.
        _ => 0,
    }
}

// fn slot_label(slot: Slot) -> &'static str {
//     match slot {
//         Slot::Authentication => "9a",
//         Slot::Signature => "9c",
//         Slot::KeyManagement => "9d",
//         Slot::CardAuth => "9e",
//         _ => "",
//     }
// }

/// Which PKCS#11 object a given [`PivObject`] represents.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ObjectClass {
    Certificate,
    PublicKey,
    PrivateKey,
    Data,
    AttestationCertificate,
}

/// A flat, per-(slot, class) enumeration whose value doubles as the
/// `CK_OBJECT_HANDLE` for that object — matching how ykcs11.c's own
/// `piv_obj_id_t` enum is cast directly into a `CK_OBJECT_HANDLE`
/// (ykcs11.c:2018). `0` is skipped (left unassigned) since PKCS#11 reserves
/// it as `CK_INVALID_HANDLE`.
// TODO: this is mostly from OpenSC, how to give credit?
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PivObjectId {
    PIV_DATA_OBJ_X509_PIV_AUTH = 1,     // PIV authentication
    PIV_DATA_OBJ_X509_DS,           // Digital signature
    PIV_DATA_OBJ_X509_KM,           // Key management
    PIV_DATA_OBJ_X509_CARD_AUTH,    // Card authentication
    PIV_DATA_OBJ_X509_RETIRED1,     // Retired key 1
    PIV_DATA_OBJ_X509_RETIRED2,     // Retired key 2
    PIV_DATA_OBJ_X509_RETIRED3,     // Retired key 3
    PIV_DATA_OBJ_X509_RETIRED4,     // Retired key 4
    PIV_DATA_OBJ_X509_RETIRED5,     // Retired key 5
    PIV_DATA_OBJ_X509_RETIRED6,     // Retired key 6
    PIV_DATA_OBJ_X509_RETIRED7,     // Retired key 7
    PIV_DATA_OBJ_X509_RETIRED8,     // Retired key 8
    PIV_DATA_OBJ_X509_RETIRED9,     // Retired key 9
    PIV_DATA_OBJ_X509_RETIRED10,    // Retired key 10
    PIV_DATA_OBJ_X509_RETIRED11,    // Retired key 11
    PIV_DATA_OBJ_X509_RETIRED12,    // Retired key 12
    PIV_DATA_OBJ_X509_RETIRED13,    // Retired key 13
    PIV_DATA_OBJ_X509_RETIRED14,    // Retired key 14
    PIV_DATA_OBJ_X509_RETIRED15,    // Retired key 15
    PIV_DATA_OBJ_X509_RETIRED16,    // Retired key 16
    PIV_DATA_OBJ_X509_RETIRED17,    // Retired key 17
    PIV_DATA_OBJ_X509_RETIRED18,    // Retired key 18
    PIV_DATA_OBJ_X509_RETIRED19,    // Retired key 19
    PIV_DATA_OBJ_X509_RETIRED20,    // Retired key 20
    PIV_DATA_OBJ_X509_ATTESTATION,  // Attestation key
    PIV_DATA_OBJ_CCC,               // Card capability container
    PIV_DATA_OBJ_CHUI,              // Cardholder unique id
    PIV_DATA_OBJ_CHF,               // Cardholder fingerprints
    PIV_DATA_OBJ_SEC_OBJ,           // Security object
    PIV_DATA_OBJ_CHFI,              // Cardholder facial images
    PIV_DATA_OBJ_PI,                // Cardholder printed information
    PIV_DATA_OBJ_DISCOVERY,         // Discovery object
    PIV_DATA_OBJ_HISTORY,           // History object
    PIV_DATA_OBJ_IRIS_IMAGE,        // Cardholder iris images
    PIV_DATA_OBJ_BITGT,             // Biometric information templates group template
    PIV_DATA_OBJ_SM_SIGNER,         // Secure messaging signer
    PIV_DATA_OBJ_PC_REF_DATA,       // Pairing code reference data

    PIV_CERT_OBJ_X509_PIV_AUTH,     // Certificate for PIV authentication
    PIV_CERT_OBJ_X509_DS,           // Certificate for digital signature
    PIV_CERT_OBJ_X509_KM,           // Certificate for key management
    PIV_CERT_OBJ_X509_CARD_AUTH,    // Certificate for card authentication
    PIV_CERT_OBJ_X509_RETIRED1,     // Certificate for retired key 1
    PIV_CERT_OBJ_X509_RETIRED2,     // Certificate for retired key 2
    PIV_CERT_OBJ_X509_RETIRED3,     // Certificate for retired key 3
    PIV_CERT_OBJ_X509_RETIRED4,     // Certificate for retired key 4
    PIV_CERT_OBJ_X509_RETIRED5,     // Certificate for retired key 5
    PIV_CERT_OBJ_X509_RETIRED6,     // Certificate for retired key 6
    PIV_CERT_OBJ_X509_RETIRED7,     // Certificate for retired key 7
    PIV_CERT_OBJ_X509_RETIRED8,     // Certificate for retired key 8
    PIV_CERT_OBJ_X509_RETIRED9,     // Certificate for retired key 9
    PIV_CERT_OBJ_X509_RETIRED10,    // Certificate for retired key 10
    PIV_CERT_OBJ_X509_RETIRED11,    // Certificate for retired key 11
    PIV_CERT_OBJ_X509_RETIRED12,    // Certificate for retired key 12
    PIV_CERT_OBJ_X509_RETIRED13,    // Certificate for retired key 13
    PIV_CERT_OBJ_X509_RETIRED14,    // Certificate for retired key 14
    PIV_CERT_OBJ_X509_RETIRED15,    // Certificate for retired key 15
    PIV_CERT_OBJ_X509_RETIRED16,    // Certificate for retired key 16
    PIV_CERT_OBJ_X509_RETIRED17,    // Certificate for retired key 17
    PIV_CERT_OBJ_X509_RETIRED18,    // Certificate for retired key 18
    PIV_CERT_OBJ_X509_RETIRED19,    // Certificate for retired key 19
    PIV_CERT_OBJ_X509_RETIRED20,    // Certificate for retired key 20
    PIV_CERT_OBJ_X509_ATTESTATION,  // Certificate for attestation

    PIV_CERT_OBJ_X509_ATTESTATION_PIV_AUTH, // Attestation certificate for PIV_AUTH
    PIV_CERT_OBJ_X509_ATTESTATION_DS, // Attestation certificate for DS
    PIV_CERT_OBJ_X509_ATTESTATION_KM, // Attestation certificate for KM
    PIV_CERT_OBJ_X509_ATTESTATION_CARD_AUTH, // Attestation certificate for CARD_AUTH
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED1, // Attestation certificate for RETIRED1
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED2, // Attestation certificate for RETIRED2
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED3, // Attestation certificate for RETIRED3
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED4, // Attestation certificate for RETIRED4
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED5, // Attestation certificate for RETIRED5
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED6, // Attestation certificate for RETIRED6
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED7, // Attestation certificate for RETIRED7
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED8, // Attestation certificate for RETIRED8
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED9, // Attestation certificate for RETIRED9
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED10, // Attestation certificate for RETIRED10
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED11, // Attestation certificate for RETIRED11
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED12, // Attestation certificate for RETIRED12
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED13, // Attestation certificate for RETIRED13
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED14, // Attestation certificate for RETIRED14
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED15, // Attestation certificate for RETIRED15
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED16, // Attestation certificate for RETIRED16
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED17, // Attestation certificate for RETIRED17
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED18, // Attestation certificate for RETIRED18
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED19, // Attestation certificate for RETIRED19
    PIV_CERT_OBJ_X509_ATTESTATION_RETIRED20, // Attestation certificate for RETIRED20

    PIV_PVTK_OBJ_PIV_AUTH,          // Private key for PIV authentication
    PIV_PVTK_OBJ_DS,                // Private key for digital signature
    PIV_PVTK_OBJ_KM,                // Private key for key management
    PIV_PVTK_OBJ_CARD_AUTH,         // Private key for card authentication
    PIV_PVTK_OBJ_RETIRED1,          // Private key for retired key 1
    PIV_PVTK_OBJ_RETIRED2,          // Private key for retired key 2
    PIV_PVTK_OBJ_RETIRED3,          // Private key for retired key 3
    PIV_PVTK_OBJ_RETIRED4,          // Private key for retired key 4
    PIV_PVTK_OBJ_RETIRED5,          // Private key for retired key 5
    PIV_PVTK_OBJ_RETIRED6,          // Private key for retired key 6
    PIV_PVTK_OBJ_RETIRED7,          // Private key for retired key 7
    PIV_PVTK_OBJ_RETIRED8,          // Private key for retired key 8
    PIV_PVTK_OBJ_RETIRED9,          // Private key for retired key 9
    PIV_PVTK_OBJ_RETIRED10,         // Private key for retired key 10
    PIV_PVTK_OBJ_RETIRED11,         // Private key for retired key 11
    PIV_PVTK_OBJ_RETIRED12,         // Private key for retired key 12
    PIV_PVTK_OBJ_RETIRED13,         // Private key for retired key 13
    PIV_PVTK_OBJ_RETIRED14,         // Private key for retired key 14
    PIV_PVTK_OBJ_RETIRED15,         // Private key for retired key 15
    PIV_PVTK_OBJ_RETIRED16,         // Private key for retired key 16
    PIV_PVTK_OBJ_RETIRED17,         // Private key for retired key 17
    PIV_PVTK_OBJ_RETIRED18,         // Private key for retired key 18
    PIV_PVTK_OBJ_RETIRED19,         // Private key for retired key 19
    PIV_PVTK_OBJ_RETIRED20,         // Private key for retired key 20
    PIV_PVTK_OBJ_ATTESTATION,       // Private key for Attestation

    PIV_PUBK_OBJ_PIV_AUTH,          // Public key for PIV authentication
    PIV_PUBK_OBJ_DS,                // Public key for digital signature
    PIV_PUBK_OBJ_KM,                // Public key for key management
    PIV_PUBK_OBJ_CARD_AUTH,         // Public key for card authentication
    PIV_PUBK_OBJ_RETIRED1,          // Public key for retired key 1
    PIV_PUBK_OBJ_RETIRED2,          // Public key for retired key 2
    PIV_PUBK_OBJ_RETIRED3,          // Public key for retired key 3
    PIV_PUBK_OBJ_RETIRED4,          // Public key for retired key 4
    PIV_PUBK_OBJ_RETIRED5,          // Public key for retired key 5
    PIV_PUBK_OBJ_RETIRED6,          // Public key for retired key 6
    PIV_PUBK_OBJ_RETIRED7,          // Public key for retired key 7
    PIV_PUBK_OBJ_RETIRED8,          // Public key for retired key 8
    PIV_PUBK_OBJ_RETIRED9,          // Public key for retired key 9
    PIV_PUBK_OBJ_RETIRED10,         // Public key for retired key 10
    PIV_PUBK_OBJ_RETIRED11,         // Public key for retired key 11
    PIV_PUBK_OBJ_RETIRED12,         // Public key for retired key 12
    PIV_PUBK_OBJ_RETIRED13,         // Public key for retired key 13
    PIV_PUBK_OBJ_RETIRED14,         // Public key for retired key 14
    PIV_PUBK_OBJ_RETIRED15,         // Public key for retired key 15
    PIV_PUBK_OBJ_RETIRED16,         // Public key for retired key 16
    PIV_PUBK_OBJ_RETIRED17,         // Public key for retired key 17
    PIV_PUBK_OBJ_RETIRED18,         // Public key for retired key 18
    PIV_PUBK_OBJ_RETIRED19,         // Public key for retired key 19
    PIV_PUBK_OBJ_RETIRED20,         // Public key for retired key 20
    PIV_PUBK_OBJ_ATTESTATION,       // Public key for Attestation
    PIV_SECRET_OBJ,
}

impl PivObjectId {
    /// `None` for any `(class, slot)` pair this module doesn't model yet
    /// (the 20 retired slots, the standalone attestation slot).
    fn from_slot_class(class: ObjectClass, slot: Slot) -> Self {
        match slot {
            Slot::Authentication => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_PIV_AUTH,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_PIV_AUTH,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_PIV_AUTH,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_PIV_AUTH,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_PIV_AUTH
                }
            },
            Slot::Signature => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_DS,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_DS,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_DS,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_DS,
                ObjectClass::AttestationCertificate => Self::PIV_CERT_OBJ_X509_ATTESTATION_DS,
            },
            Slot::KeyManagement => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_KM,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_KM,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_KM,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_KM,
                ObjectClass::AttestationCertificate => Self::PIV_CERT_OBJ_X509_ATTESTATION_KM,
            },
            Slot::CardAuth => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_CARD_AUTH,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_CARD_AUTH,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_CARD_AUTH,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_CARD_AUTH,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_CARD_AUTH
                }
            },
            Slot::Retired1 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED1,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED1,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED1,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED1,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED1
                }
            },


            Slot::Retired2 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED2,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED2,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED2,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED2,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED2
                }
            },
            Slot::Retired3 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED3,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED3,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED3,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED3,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED3
                }
            },
            Slot::Retired4 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED4,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED4,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED4,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED4,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED4
                }
            },
            Slot::Retired5 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED5,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED5,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED5,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED5,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED5
                }
            },
            Slot::Retired6 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED6,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED6,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED6,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED6,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED6
                }
            },
            Slot::Retired7 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED7,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED7,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED7,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED7,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED7
                }
            },
            Slot::Retired8 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED8,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED8,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED8,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED8,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED8
                }
            },
            Slot::Retired9 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED9,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED9,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED9,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED9,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED9
                }
            },
            Slot::Retired10 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED10,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED10,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED10,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED10,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED10
                }
            },
            Slot::Retired11 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED11,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED11,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED11,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED11,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED11
                }
            },
            Slot::Retired12 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED12,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED12,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED12,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED12,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED12
                }
            },
            Slot::Retired13 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED13,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED13,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED13,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED13,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED13
                }
            },
            Slot::Retired14 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED14,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED14,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED14,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED14,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED14
                }
            },
            Slot::Retired15 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED15,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED15,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED15,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED15,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED15
                }
            },
            Slot::Retired16 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED16,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED16,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED16,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED16,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED16
                }
            },
            Slot::Retired17 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED17,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED17,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED17,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED17,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED17
                }
            },
            Slot::Retired18 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED18,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED18,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED18,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED18,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED18
                }
            },
            Slot::Retired19 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED19,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED19,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED19,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED19,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED19
                }
            },
            Slot::Retired20 => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED20,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED20,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED20,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED20,
                ObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED20
                }
            },
            Slot::Attestation => match class {
                ObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_ATTESTATION,
                ObjectClass::PublicKey => Self::PIV_PUBK_OBJ_ATTESTATION,
                ObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_ATTESTATION,
                ObjectClass::Data => Self::PIV_DATA_OBJ_X509_ATTESTATION,
                ObjectClass::AttestationCertificate => unreachable!(),
            }
            // yubikit::piv::Slot is #[non_exhaustive] — every slot that
            // exists today is covered above, this only guards future
            // additions.
            _ => unreachable!("unsupported PIV slot"),
        }
    }

    fn label(self) -> &'static str {
        match self {
            PivObjectId::PIV_DATA_OBJ_X509_PIV_AUTH => "X.509 Certificate for PIV Authentication",
            PivObjectId::PIV_DATA_OBJ_X509_DS => "X.509 Certificate for Digital Signature",
            PivObjectId::PIV_DATA_OBJ_X509_KM => "X.509 Certificate for Key Management",
            PivObjectId::PIV_DATA_OBJ_X509_CARD_AUTH => "X.509 Certificate for Card Authentication",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED1 => "X.509 Certificate for Retired Key 1",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED2 => "X.509 Certificate for Retired Key 2",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED3 => "X.509 Certificate for Retired Key 3",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED4 => "X.509 Certificate for Retired Key 4",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED5 => "X.509 Certificate for Retired Key 5",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED6 => "X.509 Certificate for Retired Key 6",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED7 => "X.509 Certificate for Retired Key 7",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED8 => "X.509 Certificate for Retired Key 8",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED9 => "X.509 Certificate for Retired Key 9",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED10 => "X.509 Certificate for Retired Key 10",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED11 => "X.509 Certificate for Retired Key 11",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED12 => "X.509 Certificate for Retired Key 12",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED13 => "X.509 Certificate for Retired Key 13",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED14 => "X.509 Certificate for Retired Key 14",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED15 => "X.509 Certificate for Retired Key 15",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED16 => "X.509 Certificate for Retired Key 16",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED17 => "X.509 Certificate for Retired Key 17",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED18 => "X.509 Certificate for Retired Key 18",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED19 => "X.509 Certificate for Retired Key 19",
            PivObjectId::PIV_DATA_OBJ_X509_RETIRED20 => "X.509 Certificate for Retired Key 20",
            PivObjectId::PIV_DATA_OBJ_X509_ATTESTATION => "X.509 Certificate for PIV Attestation",

            PivObjectId::PIV_DATA_OBJ_CCC => "Card Capability Container",
            PivObjectId::PIV_DATA_OBJ_CHUI => "Card Holder Unique Identifier",
            PivObjectId::PIV_DATA_OBJ_CHF => "Card Holder Fingerprints",
            PivObjectId::PIV_DATA_OBJ_SEC_OBJ => "Security Object",
            PivObjectId::PIV_DATA_OBJ_CHFI => "Cardholder Facial Images",
            PivObjectId::PIV_DATA_OBJ_PI => "Printed Information",
            PivObjectId::PIV_DATA_OBJ_DISCOVERY => "Discovery Object",
            PivObjectId::PIV_DATA_OBJ_HISTORY => "Key History Object",
            PivObjectId::PIV_DATA_OBJ_IRIS_IMAGE => "Cardholder Iris Images",
            PivObjectId::PIV_DATA_OBJ_BITGT => "Biometric Information Templates Group Template",
            PivObjectId::PIV_DATA_OBJ_SM_SIGNER => "Secure Messaging Certificate Signer",
            PivObjectId::PIV_DATA_OBJ_PC_REF_DATA => "Pairing Code Reference Data Container",

            PivObjectId::PIV_CERT_OBJ_X509_PIV_AUTH => "X.509 Certificate for PIV Authentication",
            PivObjectId::PIV_CERT_OBJ_X509_DS => "X.509 Certificate for Digital Signature",
            PivObjectId::PIV_CERT_OBJ_X509_KM => "X.509 Certificate for Key Management",
            PivObjectId::PIV_CERT_OBJ_X509_CARD_AUTH => "X.509 Certificate for Card Authentication",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED1 => "X.509 Certificate for Retired Key 1",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED2 => "X.509 Certificate for Retired Key 2",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED3 => "X.509 Certificate for Retired Key 3",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED4 => "X.509 Certificate for Retired Key 4",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED5 => "X.509 Certificate for Retired Key 5",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED6 => "X.509 Certificate for Retired Key 6",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED7 => "X.509 Certificate for Retired Key 7",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED8 => "X.509 Certificate for Retired Key 8",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED9 => "X.509 Certificate for Retired Key 9",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED10 => "X.509 Certificate for Retired Key 10",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED11 => "X.509 Certificate for Retired Key 11",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED12 => "X.509 Certificate for Retired Key 12",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED13 => "X.509 Certificate for Retired Key 13",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED14 => "X.509 Certificate for Retired Key 14",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED15 => "X.509 Certificate for Retired Key 15",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED16 => "X.509 Certificate for Retired Key 16",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED17 => "X.509 Certificate for Retired Key 17",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED18 => "X.509 Certificate for Retired Key 18",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED19 => "X.509 Certificate for Retired Key 19",
            PivObjectId::PIV_CERT_OBJ_X509_RETIRED20 => "X.509 Certificate for Retired Key 20",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION => "X.509 Certificate for PIV Attestation",

            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_PIV_AUTH => "X.509 Certificate for PIV Attestation 9a",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_DS => "X.509 Certificate for PIV Attestation 9c",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_KM => "X.509 Certificate for PIV Attestation 9d",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_CARD_AUTH => "X.509 Certificate for PIV Attestation 9e",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED1 => "X.509 Certificate for PIV Attestation 82",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED2 => "X.509 Certificate for PIV Attestation 83",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED3 => "X.509 Certificate for PIV Attestation 84",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED4 => "X.509 Certificate for PIV Attestation 85",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED5 => "X.509 Certificate for PIV Attestation 86",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED6 => "X.509 Certificate for PIV Attestation 87",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED7 => "X.509 Certificate for PIV Attestation 88",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED8 => "X.509 Certificate for PIV Attestation 89",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED9 => "X.509 Certificate for PIV Attestation 8a",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED10 => "X.509 Certificate for PIV Attestation 8b",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED11 => "X.509 Certificate for PIV Attestation 8c",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED12 => "X.509 Certificate for PIV Attestation 8d",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED13 => "X.509 Certificate for PIV Attestation 8e",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED14 => "X.509 Certificate for PIV Attestation 8f",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED15 => "X.509 Certificate for PIV Attestation 90",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED16 => "X.509 Certificate for PIV Attestation 91",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED17 => "X.509 Certificate for PIV Attestation 92",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED18 => "X.509 Certificate for PIV Attestation 93",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED19 => "X.509 Certificate for PIV Attestation 94",
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED20 => "X.509 Certificate for PIV Attestation 95",

            PivObjectId::PIV_PVTK_OBJ_PIV_AUTH => "Private key for PIV Authentication",
            PivObjectId::PIV_PVTK_OBJ_DS => "Private key for Digital Signature",
            PivObjectId::PIV_PVTK_OBJ_KM => "Private key for Key Management",
            PivObjectId::PIV_PVTK_OBJ_CARD_AUTH => "Private key for Card Authentication",
            PivObjectId::PIV_PVTK_OBJ_RETIRED1 => "Private key for Retired Key 1",
            PivObjectId::PIV_PVTK_OBJ_RETIRED2 => "Private key for Retired Key 2",
            PivObjectId::PIV_PVTK_OBJ_RETIRED3 => "Private key for Retired Key 3",
            PivObjectId::PIV_PVTK_OBJ_RETIRED4 => "Private key for Retired Key 4",
            PivObjectId::PIV_PVTK_OBJ_RETIRED5 => "Private key for Retired Key 5",
            PivObjectId::PIV_PVTK_OBJ_RETIRED6 => "Private key for Retired Key 6",
            PivObjectId::PIV_PVTK_OBJ_RETIRED7 => "Private key for Retired Key 7",
            PivObjectId::PIV_PVTK_OBJ_RETIRED8 => "Private key for Retired Key 8",
            PivObjectId::PIV_PVTK_OBJ_RETIRED9 => "Private key for Retired Key 9",
            PivObjectId::PIV_PVTK_OBJ_RETIRED10 => "Private key for Retired Key 10",
            PivObjectId::PIV_PVTK_OBJ_RETIRED11 => "Private key for Retired Key 11",
            PivObjectId::PIV_PVTK_OBJ_RETIRED12 => "Private key for Retired Key 12",
            PivObjectId::PIV_PVTK_OBJ_RETIRED13 => "Private key for Retired Key 13",
            PivObjectId::PIV_PVTK_OBJ_RETIRED14 => "Private key for Retired Key 14",
            PivObjectId::PIV_PVTK_OBJ_RETIRED15 => "Private key for Retired Key 15",
            PivObjectId::PIV_PVTK_OBJ_RETIRED16 => "Private key for Retired Key 16",
            PivObjectId::PIV_PVTK_OBJ_RETIRED17 => "Private key for Retired Key 17",
            PivObjectId::PIV_PVTK_OBJ_RETIRED18 => "Private key for Retired Key 18",
            PivObjectId::PIV_PVTK_OBJ_RETIRED19 => "Private key for Retired Key 19",
            PivObjectId::PIV_PVTK_OBJ_RETIRED20 => "Private key for Retired Key 20",
            PivObjectId::PIV_PVTK_OBJ_ATTESTATION => "Private key for PIV Attestation",

            PivObjectId::PIV_PUBK_OBJ_PIV_AUTH => "Public key for PIV Authentication",
            PivObjectId::PIV_PUBK_OBJ_DS => "Public key for Digital Signature",
            PivObjectId::PIV_PUBK_OBJ_KM => "Public key for Key Management",
            PivObjectId::PIV_PUBK_OBJ_CARD_AUTH => "Public key for Card Authentication",
            PivObjectId::PIV_PUBK_OBJ_RETIRED1 => "Public key for Retired Key 1",
            PivObjectId::PIV_PUBK_OBJ_RETIRED2 => "Public key for Retired Key 2",
            PivObjectId::PIV_PUBK_OBJ_RETIRED3 => "Public key for Retired Key 3",
            PivObjectId::PIV_PUBK_OBJ_RETIRED4 => "Public key for Retired Key 4",
            PivObjectId::PIV_PUBK_OBJ_RETIRED5 => "Public key for Retired Key 5",
            PivObjectId::PIV_PUBK_OBJ_RETIRED6 => "Public key for Retired Key 6",
            PivObjectId::PIV_PUBK_OBJ_RETIRED7 => "Public key for Retired Key 7",
            PivObjectId::PIV_PUBK_OBJ_RETIRED8 => "Public key for Retired Key 8",
            PivObjectId::PIV_PUBK_OBJ_RETIRED9 => "Public key for Retired Key 9",
            PivObjectId::PIV_PUBK_OBJ_RETIRED10 => "Public key for Retired Key 10",
            PivObjectId::PIV_PUBK_OBJ_RETIRED11 => "Public key for Retired Key 11",
            PivObjectId::PIV_PUBK_OBJ_RETIRED12 => "Public key for Retired Key 12",
            PivObjectId::PIV_PUBK_OBJ_RETIRED13 => "Public key for Retired Key 13",
            PivObjectId::PIV_PUBK_OBJ_RETIRED14 => "Public key for Retired Key 14",
            PivObjectId::PIV_PUBK_OBJ_RETIRED15 => "Public key for Retired Key 15",
            PivObjectId::PIV_PUBK_OBJ_RETIRED16 => "Public key for Retired Key 16",
            PivObjectId::PIV_PUBK_OBJ_RETIRED17 => "Public key for Retired Key 17",
            PivObjectId::PIV_PUBK_OBJ_RETIRED18 => "Public key for Retired Key 18",
            PivObjectId::PIV_PUBK_OBJ_RETIRED19 => "Public key for Retired Key 19",
            PivObjectId::PIV_PUBK_OBJ_RETIRED20 => "Public key for Retired Key 20",
            PivObjectId::PIV_PUBK_OBJ_ATTESTATION => "Public key for PIV Attestation",

            PivObjectId::PIV_SECRET_OBJ => "Generic secret key",
        }

    }
}

/// One PKCS#11 object backed by a PIV container — one per `(slot, class)`
/// pair actually discovered, read once per slot at `C_OpenSession` time
/// (matching ykcs11.c's per-slot object cache, `objects.c`).
#[derive(Clone)]
pub struct PivObject {
    pub id: PivObjectId,
    class: ObjectClass,
    slot: Slot,
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

/// Reads the PIN/touch policy an attestation certificate asserts for its key,
/// matching `do_parse_attestation` (openssl_utils.c:348). The extension's
/// value is a 2-byte OCTET STRING: `[pin_policy, touch_policy]`.
fn parse_attestation(cert: &Certificate) -> Option<(PinPolicy, TouchPolicy)> {
    let ext = cert
        .tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|ext| ext.extn_id == OID_USAGE_POLICY)?;

    let bytes = ext.extn_value.as_bytes();
    let pin_policy = PinPolicy::from_u8(*bytes.first()?)?;
    let touch_policy = TouchPolicy::from_u8(*bytes.get(1)?)?;

    Some((pin_policy, touch_policy))
}

/// Whether a slot's key, independent of whatever certificate it might also
/// hold, is known to exist, known to be absent, or genuinely undeterminable
/// (old firmware + an imported key — attestation only works for on-device
/// generated keys, and slot metadata needs firmware >= 5.3).
enum KeyPresence {
    Present(PublicKey),
    Absent,
    Unknown,
}

/// SW 0x6A88/0x6B00 ("referenced data"/"slot" not found) is the device's
/// definitive "there's no key here" answer for both GET METADATA and ATTEST
/// (ykpiv.c:1183-1188, `SW_ERR_REFERENCE_NOT_FOUND`/`SW_ERR_INCORRECT_SLOT`
/// both translate to `YKPIV_KEY_ERROR`). Anything else (old-firmware
/// "instruction not supported", a transport error, ...) tells us nothing
/// about whether a key is actually present.
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
/// whether it also has a certificate. Mirrors ykcs11.c:991-1039's
/// attest-then-metadata chain (attestation first — it works on any firmware
/// >= 4.3, strictly more than metadata's >= 5.3 — falling back to metadata
/// only if attestation fails), but returns an explicit three-way
/// [`KeyPresence`] instead of leaving "could not determine" implicit in a
/// leftover `ykpiv_rc` value.
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
                    .tbs_certificate
                    .subject_public_key_info
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
            // usable public key out of it -- fall through and give
            // metadata a shot.
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

/// Read every standard PIV container's contents, mirroring the discovery
/// block in ykcs11.c (ykcs11.c:980-1068, run once per slot — see
/// `PivBackend::new_session_data`).
pub fn read_objects(piv: &mut ActivePivSession) -> Vec<PivObject> {
    let mut found = Vec::new();

    for slot in ALL_SLOTS {
        let (key_presence, pin_policy, touch_policy, generated, attestation_der) =
            detect_key(piv, slot);

        // The raw data object backing this container — same bytes CKO_DATA's
        // CKA_VALUE exposes (ykcs11.c:1041-1055). Independent of both the
        // key and the certificate below.
        if let Ok(raw) = piv.get_object(ObjectId::from_slot(slot)) {
            let id = PivObjectId::from_slot_class(ObjectClass::Data, slot);
            found.push(PivObject {
                id,
                class: ObjectClass::Data,
                slot,
                pin_policy,
                touch_policy,
                generated,
                public_key: None,
                cert_der: None,
                subject_der: None,
                issuer_der: None,
                serial_der: None,
                ec_params_der: None,
                data: Some(raw),
            });
        }

        // The slot's certificate (ykcs11.c:1057-1065) — independent of
        // whether `detect_key` found a key above. Scoped-down model: a cert
        // whose key isn't RSA/EC is treated the same as no cert at all.
        let mut cert_public_key = None;
        let mut ec_params_der = None;
        if let Ok(cert_der) = piv.get_certificate(slot) {
            if let Ok(cert) = Certificate::from_der(&cert_der) {
                let tbs = &cert.tbs_certificate;
                if let (Ok(subject_der), Ok(issuer_der), Ok(serial_der), Ok(spki_der)) = (
                    tbs.subject.to_der(),
                    tbs.issuer.to_der(),
                    tbs.serial_number.to_der(),
                    tbs.subject_public_key_info.to_der(),
                ) {
                    if let Ok(pk) = PublicKey::from_spki(&spki_der) {
                        if matches!(
                            pk,
                            PublicKey::Rsa(_)
                                | PublicKey::Ec(_)
                                | PublicKey::Ed25519(_)
                                | PublicKey::X25519(_)
                        ) {
                            ec_params_der = tbs
                                .subject_public_key_info
                                .algorithm
                                .parameters
                                .as_ref()
                                .and_then(|p| p.to_der().ok());
                            cert_public_key = Some(pk);
                            let id = PivObjectId::from_slot_class(ObjectClass::Certificate, slot);
                            found.push(PivObject {
                                id,
                                class: ObjectClass::Certificate,
                                slot,
                                pin_policy,
                                touch_policy,
                                generated,
                                public_key: None,
                                cert_der: Some(cert_der),
                                subject_der: Some(subject_der),
                                issuer_der: Some(issuer_der),
                                serial_der: Some(serial_der),
                                ec_params_der: ec_params_der.clone(),
                                data: None,
                            });
                        }
                    }
                }
            }
        }

        if let Some(attestation_der) = attestation_der {
            // Matches get_atst/_get_coa (objects.c:410-411) — an attestation
            // cert exposes the same CKA_SUBJECT/CKA_ISSUER/CKA_SERIAL_NUMBER
            // as a regular certificate object, just backed by a freshly
            // generated (not token-persisted) certificate.
            let (subject_der, issuer_der, serial_der) = Certificate::from_der(&attestation_der)
                .ok()
                .map(|cert| {
                    let tbs = &cert.tbs_certificate;
                    (
                        tbs.subject.to_der().ok(),
                        tbs.issuer.to_der().ok(),
                        tbs.serial_number.to_der().ok(),
                    )
                })
                .unwrap_or((None, None, None));

            let id = PivObjectId::from_slot_class(ObjectClass::AttestationCertificate, slot);
            found.push(PivObject {
                id,
                class: ObjectClass::AttestationCertificate,
                slot,
                pin_policy,
                touch_policy,
                generated,
                public_key: None,
                cert_der: Some(attestation_der),
                subject_der,
                issuer_der,
                serial_der,
                ec_params_der: None,
                data: None,
            });
        }

        // Reconcile: which public key (if any) actually backs this slot's
        // key objects. A confirmed device key always wins over the cert's
        // SPKI, even when they disagree -- the device is authoritative for
        // what C_Sign/C_Decrypt will actually use.
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
            // Undeterminable (old firmware + imported key): fall back to
            // the cert's key as a heuristic, same as ykcs11.c's own
            // fallback (ykcs11.c:1063) -- only applies when a cert exists.
            (KeyPresence::Unknown, cert_pk) => cert_pk.clone(),
        };

        if let Some(public_key) = key_public_key {
            for class in [ObjectClass::PublicKey, ObjectClass::PrivateKey] {
                let id = PivObjectId::from_slot_class(class, slot);
                found.push(PivObject {
                    id,
                    class,
                    slot,
                    pin_policy,
                    touch_policy,
                    generated,
                    public_key: Some(public_key.clone()),
                    cert_der: None,
                    subject_der: None,
                    issuer_der: None,
                    serial_der: None,
                    ec_params_der: ec_params_der.clone(),
                    data: None,
                });
            }
        }
    }

    // Non-per-slot generic data objects (token_objects[] tail,
    // token.c:107-118) — unlike everything above, these aren't tied to any
    // PIV key slot, so they're probed once per session rather than once
    // per slot. They only ever produce a `Data`-class object: their
    // sub_ids never appear in find_cert_object/find_pvtk_object/
    // find_pubk_object's lookup tables in the C reference, so no cert/key
    // objects are derived from them. The other 6 generic data objects
    // (fingerprints, facial images, printed information, iris images,
    // BITGT) are commented out of `token_objects[]` in the C reference
    // itself — not modeled here either, matching that.
    if let Ok(raw) = piv.get_object(ObjectId::Capability) {
        push_data_object(&mut found, PivObjectId::PIV_DATA_OBJ_CCC, raw);
    }
    if let Ok(raw) = piv.get_object(ObjectId::Chuid) {
        push_data_object(&mut found, PivObjectId::PIV_DATA_OBJ_CHUI, raw);
    }
    if let Ok(raw) = piv.get_object(ObjectId::Security) {
        push_data_object(&mut found, PivObjectId::PIV_DATA_OBJ_SEC_OBJ, raw);
    }
    if let Ok(raw) = piv.get_object(ObjectId::Discovery) {
        push_data_object(&mut found, PivObjectId::PIV_DATA_OBJ_DISCOVERY, raw);
    }
    if let Ok(raw) = piv.get_object(ObjectId::KeyHistory) {
        push_data_object(&mut found, PivObjectId::PIV_DATA_OBJ_HISTORY, raw);
    }
    // yubikit's ObjectId enum doesn't have these two (yet) — raw numeric
    // tags from ykpiv.h (YKPIV_OBJ_SM_SIGNER/YKPIV_OBJ_PC_REF_DATA).
    if let Ok(raw) = piv.get_object_raw(0x5fc122) {
        push_data_object(&mut found, PivObjectId::PIV_DATA_OBJ_SM_SIGNER, raw);
    }
    if let Ok(raw) = piv.get_object_raw(0x5fc123) {
        push_data_object(&mut found, PivObjectId::PIV_DATA_OBJ_PC_REF_DATA, raw);
    }

    found
}

/// Pushes a `Data`-class object that isn't tied to any PIV slot — `slot` is
/// set to an arbitrary placeholder since nothing reads it for this class
/// (`CKA_ID` for these objects comes from `data_object_cka_id`'s
/// `PivObjectId`-keyed lookup instead of `slot_cka_id`).
fn push_data_object(found: &mut Vec<PivObject>, id: PivObjectId, raw: Vec<u8>) {
    found.push(PivObject {
        id,
        class: ObjectClass::Data,
        slot: Slot::Authentication,
        pin_policy: PinPolicy::Default,
        touch_policy: TouchPolicy::Default,
        generated: false,
        public_key: None,
        cert_der: None,
        subject_der: None,
        issuer_der: None,
        serial_der: None,
        ec_params_der: None,
        data: Some(raw),
    });
}

/// Handles for every object this slot currently exposes. `include_private`
/// should be `false` while the slot isn't logged in — matches
/// `C_FindObjectsInit`'s `is_private_object` filter (ykcs11.c:1946).
pub fn object_handles(objects: &[PivObject], include_private: bool) -> Vec<CK_OBJECT_HANDLE> {
    objects
        .iter()
        .filter(|o| include_private || o.class != ObjectClass::PrivateKey)
        .map(|o| o.id as CK_OBJECT_HANDLE)
        .collect()
}

/// The PIV slot and public key backing a private-key object handle, for
/// `C_SignInit` — `None` for any handle that isn't a `CKO_PRIVATE_KEY`
/// object, matching `C_SignInit`'s own
/// `hKey < PIV_PVTK_OBJ_PIV_AUTH || hKey > PIV_PVTK_OBJ_ATTESTATION` range
/// check (ykcs11.c:2872), just expressed via the object's class instead of
/// a contiguous handle range.
pub fn find_signing_key(objects: &[PivObject], handle: CK_OBJECT_HANDLE) -> Option<(Slot, &PublicKey)> {
    let obj = objects.iter().find(|o| o.id as CK_OBJECT_HANDLE == handle)?;
    if obj.class != ObjectClass::PrivateKey {
        return None;
    }
    Some((obj.slot, obj.public_key.as_ref()?))
}

/// The public key backing a `CKO_PUBLIC_KEY` object handle, for
/// `C_VerifyInit` — `None` for any handle that isn't a public-key object
/// (certificates are not accepted, matching `C_VerifyInit`'s own
/// `hKey < PIV_PUBK_OBJ_PIV_AUTH || hKey > PIV_PUBK_OBJ_ATTESTATION` range
/// check, ykcs11.c:3189). No `Slot`/device access needed — verification
/// never touches the token.
pub fn find_verify_key(objects: &[PivObject], handle: CK_OBJECT_HANDLE) -> Option<&PublicKey> {
    let obj = objects.iter().find(|o| o.id as CK_OBJECT_HANDLE == handle)?;
    if obj.class != ObjectClass::PublicKey {
        return None;
    }
    obj.public_key.as_ref()
}

pub fn get_attribute(
    objects: &[PivObject],
    handle: CK_OBJECT_HANDLE,
    attr_type: CK_ATTRIBUTE_TYPE,
) -> Option<Vec<u8>> {
    let obj = objects.iter().find(|o| o.id as CK_OBJECT_HANDLE == handle)?;
    match obj.class {
        ObjectClass::Certificate => get_cert_attribute(obj, attr_type, true),
        ObjectClass::PublicKey => get_pubkey_attribute(obj, attr_type),
        ObjectClass::PrivateKey => get_privkey_attribute(obj, attr_type),
        ObjectClass::Data => get_data_attribute(obj, attr_type),
        // Matches get_atst (objects.c:410-411) — identical to a regular
        // certificate object, except CKA_TOKEN is false (it's generated
        // fresh each session, not persisted on the token).
        ObjectClass::AttestationCertificate => get_cert_attribute(obj, attr_type, false),
    }
}

fn cka_bool(b: bool) -> Vec<u8> {
    vec![b as u8]
}

// Takes a plain u32 since every caller passes either a bindgen CKx constant
// (always u32, regardless of CK_ULONG's platform-dependent width) or a
// small derived value — writes out the full native CK_ULONG width/encoding.
fn cka_ulong(v: u32) -> Vec<u8> {
    (v as CK_ULONG).to_ne_bytes().to_vec()
}

fn key_type_attr(key: &PublicKey) -> Option<Vec<u8>> {
    let kt = match key {
        PublicKey::Rsa(_) => CKK_RSA,
        PublicKey::Ec(_) => CKK_EC,
        // Matches do_get_key_type (openssl_utils.c:372-373).
        PublicKey::Ed25519(_) => CKK_EC_EDWARDS,
        PublicKey::X25519(_) => CKK_EC_MONTGOMERY,
        _ => return None,
    };
    Some(cka_ulong(kt))
}

/// `CKA_EC_PARAMS` for Ed25519/X25519 keys isn't a real OID — yubico-piv-tool
/// encodes it as a PrintableString naming the curve instead (objects.c:42-43),
/// since RFC 8410 SPKI for these algorithms carries no AlgorithmIdentifier
/// parameters to derive it from the certificate. Byte-for-byte match with the
/// C reference, quirky length byte (X25519's declared length doesn't match
/// its actual content length) included.
const ED25519_CURVE_PARAMS: &[u8] = &[
    0x13, 0x0c, b'e', b'd', b'w', b'a', b'r', b'd', b's', b'2', b'5', b'5', b'1', b'9',
];
const X25519_CURVE_PARAMS: &[u8] = &[
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

/// `CKA_EC_POINT` content for any point-shaped key — SEC1 uncompressed
/// bytes for NIST/Brainpool EC, or the raw 32-byte key for Ed25519/X25519
/// (both wrapped in a DER OCTET STRING by `ec_point_attr`, matching
/// `do_get_public_key`'s identical treatment of all three in the C
/// reference: openssl_utils.c:517-549).
fn ec_point_bytes(public_key: &PublicKey) -> Option<Vec<u8>> {
    match public_key {
        PublicKey::Ec(k) => ec_point_attr(&k.point),
        PublicKey::Ed25519(k) => ec_point_attr(&k.key),
        PublicKey::X25519(k) => ec_point_attr(&k.key),
        _ => None,
    }
}

/// `CKA_EC_POINT` is the DER encoding of an OCTET STRING wrapping the raw
/// SEC1 point — not the raw point bytes themselves (a common PKCS#11
/// interop gotcha; matches `do_get_public_key` in ykcs11.c's `objects.c`).
fn ec_point_attr(point: &[u8]) -> Option<Vec<u8>> {
    der::asn1::OctetStringRef::new(point).ok()?.to_der().ok()
}

// Matches _get_coa (objects.c:406-539), shared by get_coa (token=true) and
// get_atst (token=false) in the C reference.
fn get_cert_attribute(obj: &PivObject, attr_type: CK_ATTRIBUTE_TYPE, token: bool) -> Option<Vec<u8>> {
    yk_dbg!("For certificate object {}, get ", obj.id as CK_OBJECT_HANDLE);
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
            Some(vec![slot_cka_id(obj.slot)])
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

// Matches get_puoa (objects.c:844-1121).
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
            Some(vec![slot_cka_id(obj.slot)])
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

// Matches get_proa (objects.c:546-831). Modulus/EC attributes mirror the
// public-key object — the device never discloses private key material
// itself (objects.c:710-774).
fn get_privkey_attribute(obj: &PivObject, attr_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
    let public_key = obj.public_key.as_ref()?;
    yk_dbg!("For private key object {}, get ", obj.id as CK_OBJECT_HANDLE);
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
            Some(vec![slot_cka_id(obj.slot)])
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
            // pvtkey_objects[25] (the attestation key) is all-zero in the C
            // reference (objects.c:266) — it can't decrypt, sign, or do
            // anything besides exist.
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
/// object's container, as raw DER content octets (no tag/length header) —
/// matches the `data_objects[]` table's encoding (objects.c:199-238), which
/// `get_doa`'s `CKA_OBJECT_ID` case returns byte-for-byte as-is.
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
        PivObjectId::PIV_DATA_OBJ_CCC => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x01, 0x81, 0x5b, 0x00])
        }
        // 2.16.840.1.101.3.7.2.48.0
        PivObjectId::PIV_DATA_OBJ_CHUI => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x30, 0x00])
        }
        // 2.16.840.1.101.3.7.2.144.0
        PivObjectId::PIV_DATA_OBJ_SEC_OBJ => {
            Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x07, 0x02, 0x81, 0x10, 0x00])
        }
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

// Matches get_doa (objects.c:303-400).
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
                _ => slot_cka_id(obj.slot),
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
