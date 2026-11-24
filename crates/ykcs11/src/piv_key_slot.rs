use yubikit::piv::Slot;

/// Which PKCS#11 object a given [`PivObject`] represents.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PivObjectClass {
    Certificate,
    PublicKey,
    PrivateKey,
    Data,
    AttestationCertificate,
    /// the ECDH shared secret `C_DeriveKey` produces.
    /// Unlike the other classes, this isn't one-per-slot but a single
    /// global object overwritten each time `C_DeriveKey` runs.
    SecretKey,
}

/// A flat, per-(slot, class) enumeration whose value doubles as the
/// `CK_OBJECT_HANDLE` for that object.
// TODO: this is mostly from OpenSC, how to give credit?
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PivObjectId {
    PIV_DATA_OBJ_X509_PIV_AUTH = 1, // PIV authentication
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

    PIV_CERT_OBJ_X509_PIV_AUTH,    // Certificate for PIV authentication
    PIV_CERT_OBJ_X509_DS,          // Certificate for digital signature
    PIV_CERT_OBJ_X509_KM,          // Certificate for key management
    PIV_CERT_OBJ_X509_CARD_AUTH,   // Certificate for card authentication
    PIV_CERT_OBJ_X509_RETIRED1,    // Certificate for retired key 1
    PIV_CERT_OBJ_X509_RETIRED2,    // Certificate for retired key 2
    PIV_CERT_OBJ_X509_RETIRED3,    // Certificate for retired key 3
    PIV_CERT_OBJ_X509_RETIRED4,    // Certificate for retired key 4
    PIV_CERT_OBJ_X509_RETIRED5,    // Certificate for retired key 5
    PIV_CERT_OBJ_X509_RETIRED6,    // Certificate for retired key 6
    PIV_CERT_OBJ_X509_RETIRED7,    // Certificate for retired key 7
    PIV_CERT_OBJ_X509_RETIRED8,    // Certificate for retired key 8
    PIV_CERT_OBJ_X509_RETIRED9,    // Certificate for retired key 9
    PIV_CERT_OBJ_X509_RETIRED10,   // Certificate for retired key 10
    PIV_CERT_OBJ_X509_RETIRED11,   // Certificate for retired key 11
    PIV_CERT_OBJ_X509_RETIRED12,   // Certificate for retired key 12
    PIV_CERT_OBJ_X509_RETIRED13,   // Certificate for retired key 13
    PIV_CERT_OBJ_X509_RETIRED14,   // Certificate for retired key 14
    PIV_CERT_OBJ_X509_RETIRED15,   // Certificate for retired key 15
    PIV_CERT_OBJ_X509_RETIRED16,   // Certificate for retired key 16
    PIV_CERT_OBJ_X509_RETIRED17,   // Certificate for retired key 17
    PIV_CERT_OBJ_X509_RETIRED18,   // Certificate for retired key 18
    PIV_CERT_OBJ_X509_RETIRED19,   // Certificate for retired key 19
    PIV_CERT_OBJ_X509_RETIRED20,   // Certificate for retired key 20
    PIV_CERT_OBJ_X509_ATTESTATION, // Certificate for attestation

    PIV_CERT_OBJ_X509_ATTESTATION_PIV_AUTH, // Attestation certificate for PIV_AUTH
    PIV_CERT_OBJ_X509_ATTESTATION_DS,       // Attestation certificate for DS
    PIV_CERT_OBJ_X509_ATTESTATION_KM,       // Attestation certificate for KM
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

    PIV_PVTK_OBJ_PIV_AUTH,    // Private key for PIV authentication
    PIV_PVTK_OBJ_DS,          // Private key for digital signature
    PIV_PVTK_OBJ_KM,          // Private key for key management
    PIV_PVTK_OBJ_CARD_AUTH,   // Private key for card authentication
    PIV_PVTK_OBJ_RETIRED1,    // Private key for retired key 1
    PIV_PVTK_OBJ_RETIRED2,    // Private key for retired key 2
    PIV_PVTK_OBJ_RETIRED3,    // Private key for retired key 3
    PIV_PVTK_OBJ_RETIRED4,    // Private key for retired key 4
    PIV_PVTK_OBJ_RETIRED5,    // Private key for retired key 5
    PIV_PVTK_OBJ_RETIRED6,    // Private key for retired key 6
    PIV_PVTK_OBJ_RETIRED7,    // Private key for retired key 7
    PIV_PVTK_OBJ_RETIRED8,    // Private key for retired key 8
    PIV_PVTK_OBJ_RETIRED9,    // Private key for retired key 9
    PIV_PVTK_OBJ_RETIRED10,   // Private key for retired key 10
    PIV_PVTK_OBJ_RETIRED11,   // Private key for retired key 11
    PIV_PVTK_OBJ_RETIRED12,   // Private key for retired key 12
    PIV_PVTK_OBJ_RETIRED13,   // Private key for retired key 13
    PIV_PVTK_OBJ_RETIRED14,   // Private key for retired key 14
    PIV_PVTK_OBJ_RETIRED15,   // Private key for retired key 15
    PIV_PVTK_OBJ_RETIRED16,   // Private key for retired key 16
    PIV_PVTK_OBJ_RETIRED17,   // Private key for retired key 17
    PIV_PVTK_OBJ_RETIRED18,   // Private key for retired key 18
    PIV_PVTK_OBJ_RETIRED19,   // Private key for retired key 19
    PIV_PVTK_OBJ_RETIRED20,   // Private key for retired key 20
    PIV_PVTK_OBJ_ATTESTATION, // Private key for Attestation

    PIV_PUBK_OBJ_PIV_AUTH,    // Public key for PIV authentication
    PIV_PUBK_OBJ_DS,          // Public key for digital signature
    PIV_PUBK_OBJ_KM,          // Public key for key management
    PIV_PUBK_OBJ_CARD_AUTH,   // Public key for card authentication
    PIV_PUBK_OBJ_RETIRED1,    // Public key for retired key 1
    PIV_PUBK_OBJ_RETIRED2,    // Public key for retired key 2
    PIV_PUBK_OBJ_RETIRED3,    // Public key for retired key 3
    PIV_PUBK_OBJ_RETIRED4,    // Public key for retired key 4
    PIV_PUBK_OBJ_RETIRED5,    // Public key for retired key 5
    PIV_PUBK_OBJ_RETIRED6,    // Public key for retired key 6
    PIV_PUBK_OBJ_RETIRED7,    // Public key for retired key 7
    PIV_PUBK_OBJ_RETIRED8,    // Public key for retired key 8
    PIV_PUBK_OBJ_RETIRED9,    // Public key for retired key 9
    PIV_PUBK_OBJ_RETIRED10,   // Public key for retired key 10
    PIV_PUBK_OBJ_RETIRED11,   // Public key for retired key 11
    PIV_PUBK_OBJ_RETIRED12,   // Public key for retired key 12
    PIV_PUBK_OBJ_RETIRED13,   // Public key for retired key 13
    PIV_PUBK_OBJ_RETIRED14,   // Public key for retired key 14
    PIV_PUBK_OBJ_RETIRED15,   // Public key for retired key 15
    PIV_PUBK_OBJ_RETIRED16,   // Public key for retired key 16
    PIV_PUBK_OBJ_RETIRED17,   // Public key for retired key 17
    PIV_PUBK_OBJ_RETIRED18,   // Public key for retired key 18
    PIV_PUBK_OBJ_RETIRED19,   // Public key for retired key 19
    PIV_PUBK_OBJ_RETIRED20,   // Public key for retired key 20
    PIV_PUBK_OBJ_ATTESTATION, // Public key for Attestation
    PIV_SECRET_OBJ,
}

impl PivObjectId {
    pub(crate) fn label(self) -> &'static str {
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

            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_PIV_AUTH => {
                "X.509 Certificate for PIV Attestation 9a"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_DS => {
                "X.509 Certificate for PIV Attestation 9c"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_KM => {
                "X.509 Certificate for PIV Attestation 9d"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_CARD_AUTH => {
                "X.509 Certificate for PIV Attestation 9e"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED1 => {
                "X.509 Certificate for PIV Attestation 82"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED2 => {
                "X.509 Certificate for PIV Attestation 83"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED3 => {
                "X.509 Certificate for PIV Attestation 84"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED4 => {
                "X.509 Certificate for PIV Attestation 85"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED5 => {
                "X.509 Certificate for PIV Attestation 86"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED6 => {
                "X.509 Certificate for PIV Attestation 87"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED7 => {
                "X.509 Certificate for PIV Attestation 88"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED8 => {
                "X.509 Certificate for PIV Attestation 89"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED9 => {
                "X.509 Certificate for PIV Attestation 8a"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED10 => {
                "X.509 Certificate for PIV Attestation 8b"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED11 => {
                "X.509 Certificate for PIV Attestation 8c"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED12 => {
                "X.509 Certificate for PIV Attestation 8d"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED13 => {
                "X.509 Certificate for PIV Attestation 8e"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED14 => {
                "X.509 Certificate for PIV Attestation 8f"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED15 => {
                "X.509 Certificate for PIV Attestation 90"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED16 => {
                "X.509 Certificate for PIV Attestation 91"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED17 => {
                "X.509 Certificate for PIV Attestation 92"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED18 => {
                "X.509 Certificate for PIV Attestation 93"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED19 => {
                "X.509 Certificate for PIV Attestation 94"
            }
            PivObjectId::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED20 => {
                "X.509 Certificate for PIV Attestation 95"
            }

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

    pub(crate) fn from_slot_class(class: PivObjectClass, slot: Slot) -> Self {
        match slot {
            Slot::Authentication => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_PIV_AUTH,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_PIV_AUTH,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_PIV_AUTH,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_PIV_AUTH,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_PIV_AUTH
                }
            },
            Slot::Signature => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_DS,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_DS,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_DS,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_DS,
                PivObjectClass::AttestationCertificate => Self::PIV_CERT_OBJ_X509_ATTESTATION_DS,
            },
            Slot::KeyManagement => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_KM,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_KM,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_KM,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_KM,
                PivObjectClass::AttestationCertificate => Self::PIV_CERT_OBJ_X509_ATTESTATION_KM,
            },
            Slot::CardAuth => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_CARD_AUTH,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_CARD_AUTH,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_CARD_AUTH,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_CARD_AUTH,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_CARD_AUTH
                }
            },
            Slot::Retired1 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED1,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED1,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED1,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED1,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED1
                }
            },

            Slot::Retired2 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED2,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED2,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED2,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED2,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED2
                }
            },
            Slot::Retired3 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED3,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED3,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED3,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED3,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED3
                }
            },
            Slot::Retired4 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED4,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED4,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED4,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED4,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED4
                }
            },
            Slot::Retired5 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED5,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED5,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED5,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED5,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED5
                }
            },
            Slot::Retired6 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED6,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED6,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED6,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED6,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED6
                }
            },
            Slot::Retired7 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED7,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED7,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED7,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED7,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED7
                }
            },
            Slot::Retired8 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED8,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED8,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED8,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED8,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED8
                }
            },
            Slot::Retired9 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED9,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED9,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED9,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED9,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED9
                }
            },
            Slot::Retired10 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED10,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED10,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED10,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED10,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED10
                }
            },
            Slot::Retired11 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED11,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED11,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED11,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED11,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED11
                }
            },
            Slot::Retired12 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED12,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED12,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED12,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED12,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED12
                }
            },
            Slot::Retired13 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED13,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED13,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED13,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED13,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED13
                }
            },
            Slot::Retired14 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED14,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED14,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED14,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED14,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED14
                }
            },
            Slot::Retired15 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED15,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED15,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED15,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED15,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED15
                }
            },
            Slot::Retired16 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED16,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED16,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED16,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED16,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED16
                }
            },
            Slot::Retired17 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED17,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED17,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED17,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED17,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED17
                }
            },
            Slot::Retired18 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED18,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED18,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED18,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED18,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED18
                }
            },
            Slot::Retired19 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED19,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED19,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED19,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED19,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED19
                }
            },
            Slot::Retired20 => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_RETIRED20,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_RETIRED20,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_RETIRED20,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_RETIRED20,
                PivObjectClass::AttestationCertificate => {
                    Self::PIV_CERT_OBJ_X509_ATTESTATION_RETIRED20
                }
            },
            Slot::Attestation => match class {
                PivObjectClass::SecretKey => {
                    unreachable!("PIV_SECRET_OBJ is a singleton, not a per-slot object")
                }
                PivObjectClass::Certificate => Self::PIV_CERT_OBJ_X509_ATTESTATION,
                PivObjectClass::PublicKey => Self::PIV_PUBK_OBJ_ATTESTATION,
                PivObjectClass::PrivateKey => Self::PIV_PVTK_OBJ_ATTESTATION,
                PivObjectClass::Data => Self::PIV_DATA_OBJ_X509_ATTESTATION,
                PivObjectClass::AttestationCertificate => unreachable!(),
            },
            _ => unreachable!("unsupported PIV slot"),
        }
    }
}

/// `CKA_ID` for every object derived from this container
pub(crate) fn slot_to_ckaid(slot: Slot) -> u8 {
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
        _ => 0,
    }
}

pub(crate) fn slot_from_ckaid(id: u8) -> Option<Slot> {
    Some(match id {
        1 => Slot::Authentication,
        2 => Slot::Signature,
        3 => Slot::KeyManagement,
        4 => Slot::CardAuth,
        5 => Slot::Retired1,
        6 => Slot::Retired2,
        7 => Slot::Retired3,
        8 => Slot::Retired4,
        9 => Slot::Retired5,
        10 => Slot::Retired6,
        11 => Slot::Retired7,
        12 => Slot::Retired8,
        13 => Slot::Retired9,
        14 => Slot::Retired10,
        15 => Slot::Retired11,
        16 => Slot::Retired12,
        17 => Slot::Retired13,
        18 => Slot::Retired14,
        19 => Slot::Retired15,
        20 => Slot::Retired16,
        21 => Slot::Retired17,
        22 => Slot::Retired18,
        23 => Slot::Retired19,
        24 => Slot::Retired20,
        _ => return None,
    })
}
