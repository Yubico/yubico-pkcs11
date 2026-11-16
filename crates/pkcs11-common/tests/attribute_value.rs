use pkcs11_common::backend::*;
use pkcs11_sys::*;
use std::ptr::null_mut;

struct TestBackend;

impl Backend for TestBackend {
    type SlotData = ();
    type SessionData = ();
    type ModuleData = ();

    fn library_info() -> LibraryInfo {
        unimplemented!()
    }
    fn initialize(_: Option<&str>) -> Result<((), Vec<()>), CK_RV> {
        Ok(((), vec![()]))
    }
    fn is_present(_: &()) -> bool {
        true
    }
    fn slot_info(_: CK_SLOT_ID, _: &()) -> SlotInfo {
        unimplemented!()
    }
    fn token_info(_: &mut ()) -> Option<TokenInfo> {
        unimplemented!()
    }
    fn mechanism_list(_: &()) -> Vec<CK_MECHANISM_TYPE> {
        vec![]
    }
    fn mechanism_info(_: &(), _: CK_MECHANISM_TYPE) -> Option<MechanismInfo> {
        None
    }
    fn new_session_data(_: &mut (), _: CK_SESSION_HANDLE, _: CK_FLAGS) {}
    fn login(
        _: &mut Slot<Self>,
        _: CK_SESSION_HANDLE,
        _: CK_USER_TYPE,
        _: &[u8],
        _: &[u8],
    ) -> Result<(), CK_RV> {
        unimplemented!()
    }
    fn logout(_: &mut Slot<Self>) -> Result<(), CK_RV> {
        unimplemented!()
    }
    fn generate_random(_: &Slot<Self>, _: &mut [u8]) -> Result<(), CK_RV> {
        unimplemented!()
    }
    fn object_handles(_: &Slot<Self>) -> Vec<CK_OBJECT_HANDLE> {
        vec![1]
    }
    fn get_one_attribute_value(
        _: &(),
        _: CK_OBJECT_HANDLE,
        attr: CK_ATTRIBUTE_TYPE,
    ) -> Option<Vec<u8>> {
        match attr {
            CKA_LABEL => Some(b"label".to_vec()),
            CKA_ID => Some(vec![42]),
            _ => None,
        }
    }
}

#[test]
fn short_attribute_buffer_marks_length_unavailable_and_processes_other_attributes() {
    let engine = Engine::<TestBackend>::new();
    let mut session = 0;
    let mut short = [0xAAu8; 2];
    let mut id = [0u8; 1];
    let mut attrs = [
        CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: short.as_mut_ptr().cast(),
            ulValueLen: short.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID,
            pValue: id.as_mut_ptr().cast(),
            ulValueLen: id.len() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: null_mut(),
            ulValueLen: 0,
        },
    ];
    unsafe {
        assert_eq!(engine.initialize(null_mut()), CKR_OK.into());
        assert_eq!(
            engine.open_session(
                0,
                CKF_SERIAL_SESSION as CK_FLAGS,
                null_mut(),
                None,
                &mut session
            ),
            CKR_OK.into()
        );
        assert_eq!(
            engine.get_attribute_value(session, 1, attrs.as_mut_ptr(), attrs.len() as CK_ULONG),
            CKR_BUFFER_TOO_SMALL.into()
        );
    }
    assert_eq!(attrs[0].ulValueLen, CK_UNAVAILABLE_INFORMATION as CK_ULONG);
    assert_eq!(short, [0xAA; 2]);
    assert_eq!(attrs[1].ulValueLen, 1);
    assert_eq!(id, [42]);
    assert_eq!(attrs[2].ulValueLen, 5);
}
