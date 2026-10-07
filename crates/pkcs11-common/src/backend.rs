// Copyright 2026 Yubico AB

//! Generic Cryptoki session/slot/module engine shared by every PKCS#11
//! module in this workspace. A module implements [`Backend`] to plug its
//! own slot discovery, token identity, and login handling into the shared
//! `C_*` dispatch logic; the engine owns everything else (handle
//! allocation, session tables, login-state tracking).

use crate::session::{LoginState, compute_state};
use crate::str_pad;
use parking_lot::Mutex;
use pkcs11_sys::*;
use std::collections::HashMap;
use std::sync::Arc;

/// Fixed library identity reported by `C_GetInfo`.
pub struct LibraryInfo {
    pub manufacturer_id: &'static str,
    pub library_description: &'static str,
    pub library_version: (u8, u8),
    pub cryptoki_version: (u8, u8),
}

/// Hardware-level info reported by `C_GetSlotInfo`.
pub struct SlotInfo {
    pub description: String,
    pub manufacturer_id: String,
    pub hardware_version: (u8, u8),
    pub firmware_version: (u8, u8),
}

/// Token-level info reported by `C_GetTokenInfo`, when a token is present.
pub struct TokenInfo {
    pub label: String,
    pub manufacturer_id: String,
    pub model: String,
    pub serial_number: String,
    pub min_pin_len: CK_ULONG,
    pub max_pin_len: CK_ULONG,
    pub hardware_version: (u8, u8),
    pub firmware_version: (u8, u8),
    /// Extra CKF_* bits ORed onto the flags the engine already sets
    /// (CKF_RNG | CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED |
    /// CKF_USER_PIN_INITIALIZED) — e.g. CKF_USER_PIN_LOCKED.
    pub extra_flags: CK_FLAGS,
}

/// Per-mechanism info reported by `C_GetMechanismInfo`.
pub struct MechanismInfo {
    pub min_key_size: CK_ULONG,
    pub max_key_size: CK_ULONG,
    pub flags: CK_FLAGS,
}

/// `C_FindObjectsInit`/`C_FindObjects`/`C_FindObjectsFinal` state for one
/// session. Generic (not part of `Backend::SessionData`) since the
/// find-object protocol itself — one active search at a time, a fixed
/// result list handed out incrementally — is identical regardless of what
/// a backend's objects actually are.
#[derive(Default)]
pub struct FindOp {
    pub active: bool,
    pub matches: Vec<CK_OBJECT_HANDLE>,
    pub returned_offset: usize,
}

/// A single open session on a slot.
pub struct Session<S> {
    pub handle: CK_SESSION_HANDLE,
    pub flags: CK_FLAGS,
    pub find_op: FindOp,
    pub data: S,
}

/// One slot: backend-specific slot data plus whatever sessions are open on
/// it. Login state is tracked per-slot (shared by every session on that
/// slot), matching the Cryptoki model of one token per slot.
pub struct Slot<B: Backend> {
    pub login_state: LoginState,
    pub sessions: HashMap<CK_SESSION_HANDLE, Session<B::SessionData>>,
    pub data: B::SlotData,
}

impl<B: Backend> Slot<B> {
    pub fn new(data: B::SlotData) -> Self {
        Self {
            login_state: LoginState::Public,
            sessions: HashMap::new(),
            data,
        }
    }
}

/// Everything that exists between `C_Initialize` and `C_Finalize`.
pub struct ModuleState<B: Backend> {
    pub slots: Vec<Arc<Mutex<Slot<B>>>>,
    pub session_to_slot: HashMap<CK_SESSION_HANDLE, CK_SLOT_ID>,
    pub next_session_handle: CK_SESSION_HANDLE,
    pub data: B::ModuleData,
}

/// Backend-specific policy plugged into the shared Cryptoki engine.
///
/// A `Backend` never touches `CK_*` dispatch bookkeeping — the engine owns
/// that. It only answers "what does this slot/token look like" and "how do
/// I talk to the real device".
pub trait Backend: Sized + 'static {
    /// Extra per-slot state (e.g. the live PC/SC connection or HSM handle).
    type SlotData: Send;
    /// Extra per-session state (e.g. an established HSM session).
    type SessionData: Send;
    /// Extra module-wide state (e.g. parsed config).
    type ModuleData: Send;

    fn library_info() -> LibraryInfo;

    /// Parse the (already-extracted) `pReserved` string from
    /// `C_Initialize` and build the initial module/slot state.
    fn initialize(reserved: Option<&str>)
    -> Result<(Self::ModuleData, Vec<Self::SlotData>), CK_RV>;

    /// Backend-specific cleanup run during `C_Finalize`, before the module
    /// state is dropped. Default: nothing.
    fn finalize(_data: &mut Self::ModuleData) {}

    /// Re-scan for slots/tokens. Called at the start of every
    /// `C_GetSlotList`. Backends with a fixed, config-driven slot list can
    /// leave this at the default no-op.
    fn refresh_slots(_state: &mut ModuleState<Self>) -> Result<(), CK_RV> {
        Ok(())
    }

    fn is_present(data: &Self::SlotData) -> bool;
    fn slot_info(slot_id: CK_SLOT_ID, data: &Self::SlotData) -> SlotInfo;
    /// `None` means no token present (translated to `CKR_TOKEN_NOT_PRESENT`).
    fn token_info(data: &mut Self::SlotData) -> Option<TokenInfo>;

    /// The `CKM_*` mechanisms this token supports, in the order they should
    /// be reported. Called with the token already confirmed present.
    fn mechanism_list(data: &Self::SlotData) -> Vec<CK_MECHANISM_TYPE>;

    /// Details for one mechanism. `None` means the mechanism isn't
    /// supported (translated to `CKR_MECHANISM_INVALID`). Called with the
    /// token already confirmed present.
    fn mechanism_info(data: &Self::SlotData, mechanism: CK_MECHANISM_TYPE)
    -> Option<MechanismInfo>;

    /// Maximum concurrent sessions per slot, or `None` for unbounded
    /// (`CK_EFFECTIVELY_INFINITE`).
    fn max_sessions(_data: &Self::SlotData) -> Option<usize> {
        None
    }

    fn new_session_data(
        slot: &mut Self::SlotData,
        handle: CK_SESSION_HANDLE,
        flags: CK_FLAGS,
    ) -> Self::SessionData;

    /// `username` is the PKCS#11 3.0 `C_LoginUser` identity string, empty
    /// when called from the base `C_Login` (which has no such concept) —
    /// backends that don't distinguish users (e.g. ykcs11) can ignore it.
    fn login(
        slot: &mut Slot<Self>,
        user_type: CK_USER_TYPE,
        pin: &[u8],
        username: &[u8],
    ) -> Result<(), CK_RV>;
    fn logout(slot: &mut Slot<Self>) -> Result<(), CK_RV>;

    /// Fill `buf` with random bytes. The engine has already resolved and
    /// locked `slot`; backends needing an authenticated session (e.g.
    /// yubihsm-pkcs11, which draws randomness from the HSM itself) check
    /// `slot.login_state` themselves — the two C reference modules differ
    /// here (ykcs11 needs no login at all).
    fn generate_random(slot: &Slot<Self>, buf: &mut [u8]) -> Result<(), CK_RV>;

    /// Seed the token's RNG. Default: not supported, matching
    /// yubihsm_pkcs11.c's `C_SeedRandom`, which unconditionally returns
    /// `CKR_RANDOM_SEED_NOT_SUPPORTED`.
    fn seed_random(_slot: &Slot<Self>, _seed: &[u8]) -> Result<(), CK_RV> {
        Err(CKR_RANDOM_SEED_NOT_SUPPORTED.into())
    }

    /// Every object handle currently visible on this token, already
    /// filtered for login state (e.g. private-key objects omitted while
    /// `slot.login_state == LoginState::Public`) — matches
    /// `C_FindObjectsInit`'s `is_private_object` filter in ykcs11.c.
    fn object_handles(slot: &Slot<Self>) -> Vec<CK_OBJECT_HANDLE>;

    /// One attribute's raw value for a given object handle. `None` means
    /// the attribute doesn't apply to this object (→
    /// `CKR_ATTRIBUTE_TYPE_INVALID` at the caller) — object-handle validity
    /// itself is checked separately, against `object_handles`.
    fn get_one_attribute_value(
        data: &Self::SlotData,
        handle: CK_OBJECT_HANDLE,
        attr_type: CK_ATTRIBUTE_TYPE,
    ) -> Option<Vec<u8>>;
}

/// The shared Cryptoki engine. One `static` instance per module, generic
/// over that module's [`Backend`] impl.
pub struct Engine<B: Backend> {
    state: Mutex<Option<ModuleState<B>>>,
}

impl<B: Backend> Engine<B> {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(None),
        }
    }

    /// Extract the `pReserved` C string from a (possibly null)
    /// `CK_C_INITIALIZE_ARGS*`, shared by every module's `C_Initialize`.
    unsafe fn extract_reserved(p_init_args: CK_VOID_PTR) -> Option<String> {
        unsafe {
            if p_init_args.is_null() {
                return None;
            }
            let args = &*(p_init_args as *const CK_C_INITIALIZE_ARGS);
            if args.pReserved.is_null() {
                return None;
            }
            let c_str = std::ffi::CStr::from_ptr(args.pReserved as *const std::os::raw::c_char);
            Some(c_str.to_string_lossy().into_owned())
        }
    }

    fn slot_arc(state: &ModuleState<B>, slot_id: CK_SLOT_ID) -> Result<Arc<Mutex<Slot<B>>>, CK_RV> {
        state
            .slots
            .get(slot_id as usize)
            .cloned()
            .ok_or_else(|| CKR_SLOT_ID_INVALID.into())
    }

    pub unsafe fn initialize(&self, p_init_args: CK_VOID_PTR) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            if guard.is_some() {
                return CKR_CRYPTOKI_ALREADY_INITIALIZED.into();
            }

            let reserved = Self::extract_reserved(p_init_args);
            let (data, slot_data) = match B::initialize(reserved.as_deref()) {
                Ok(v) => v,
                Err(rv) => return rv,
            };

            let slots = slot_data
                .into_iter()
                .map(|d| Arc::new(Mutex::new(Slot::new(d))))
                .collect();

            *guard = Some(ModuleState {
                slots,
                session_to_slot: HashMap::new(),
                next_session_handle: 1,
                data,
            });

            CKR_OK.into()
        }
    }

    pub unsafe fn finalize(&self, p_reserved: CK_VOID_PTR) -> CK_RV {
        if !p_reserved.is_null() {
            return CKR_ARGUMENTS_BAD.into();
        }
        let mut guard = self.state.lock();
        let mut state = match guard.take() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
        };
        B::finalize(&mut state.data);
        CKR_OK.into()
    }

    pub unsafe fn get_info(&self, p_info: CK_INFO_PTR) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            if guard.is_none() {
                return CKR_CRYPTOKI_NOT_INITIALIZED.into();
            }
            if p_info.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let lib = B::library_info();
            let info = &mut *p_info;
            info.cryptokiVersion.major = lib.cryptoki_version.0;
            info.cryptokiVersion.minor = lib.cryptoki_version.1;
            str_pad(&mut info.manufacturerID, lib.manufacturer_id);
            info.flags = 0;
            str_pad(&mut info.libraryDescription, lib.library_description);
            info.libraryVersion.major = lib.library_version.0;
            info.libraryVersion.minor = lib.library_version.1;

            CKR_OK.into()
        }
    }

    /// Shared body for `C_GetFunctionList`: every module just points at its
    /// own `static CK_FUNCTION_LIST`.
    pub unsafe fn get_function_list(
        &self,
        pp_function_list: *mut CK_FUNCTION_LIST_PTR,
        table: &'static CK_FUNCTION_LIST,
    ) -> CK_RV {
        unsafe {
            if pp_function_list.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            *pp_function_list = table as *const CK_FUNCTION_LIST as CK_FUNCTION_LIST_PTR;
            CKR_OK.into()
        }
    }

    pub unsafe fn get_slot_list(
        &self,
        token_present: CK_BBOOL,
        p_slot_list: CK_SLOT_ID_PTR,
        pul_count: CK_ULONG_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            if pul_count.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            if let Err(rv) = B::refresh_slots(state) {
                return rv;
            }

            let mut slot_ids: Vec<CK_SLOT_ID> = Vec::new();
            for (i, slot_arc) in state.slots.iter().enumerate() {
                if token_present != 0 {
                    let slot = slot_arc.lock();
                    if !B::is_present(&slot.data) {
                        continue;
                    }
                }
                slot_ids.push(i as CK_SLOT_ID);
            }

            let count = slot_ids.len() as CK_ULONG;
            if p_slot_list.is_null() {
                *pul_count = count;
                return CKR_OK.into();
            }
            if *pul_count < count {
                *pul_count = count;
                return CKR_BUFFER_TOO_SMALL.into();
            }
            for (i, id) in slot_ids.iter().enumerate() {
                *p_slot_list.add(i) = *id;
            }
            *pul_count = count;
            CKR_OK.into()
        }
    }

    pub unsafe fn get_slot_info(&self, slot_id: CK_SLOT_ID, p_info: CK_SLOT_INFO_PTR) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            if p_info.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            let slot = match Self::slot_arc(state, slot_id) {
                Ok(s) => s,
                Err(rv) => return rv,
            };
            let slot = slot.lock();
            let sinfo = B::slot_info(slot_id, &slot.data);

            let info = &mut *p_info;
            str_pad(&mut info.slotDescription, &sinfo.description);
            str_pad(&mut info.manufacturerID, &sinfo.manufacturer_id);
            info.hardwareVersion.major = sinfo.hardware_version.0;
            info.hardwareVersion.minor = sinfo.hardware_version.1;
            info.firmwareVersion.major = sinfo.firmware_version.0;
            info.firmwareVersion.minor = sinfo.firmware_version.1;
            info.flags = CKF_HW_SLOT as CK_FLAGS | CKF_REMOVABLE_DEVICE as CK_FLAGS;
            if B::is_present(&slot.data) {
                info.flags |= CKF_TOKEN_PRESENT as CK_FLAGS;
            }
            CKR_OK.into()
        }
    }

    pub unsafe fn get_mechanism_list(
        &self,
        slot_id: CK_SLOT_ID,
        p_mechanism_list: CK_MECHANISM_TYPE_PTR,
        pul_count: CK_ULONG_PTR,
    ) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            if pul_count.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            let slot = match Self::slot_arc(state, slot_id) {
                Ok(s) => s,
                Err(rv) => return rv,
            };
            let slot = slot.lock();
            if !B::is_present(&slot.data) {
                return CKR_TOKEN_NOT_PRESENT.into();
            }
            let mechanisms = B::mechanism_list(&slot.data);

            let count = mechanisms.len() as CK_ULONG;
            if p_mechanism_list.is_null() {
                *pul_count = count;
                return CKR_OK.into();
            }
            if *pul_count < count {
                *pul_count = count;
                return CKR_BUFFER_TOO_SMALL.into();
            }
            for (i, m) in mechanisms.iter().enumerate() {
                *p_mechanism_list.add(i) = *m;
            }
            *pul_count = count;
            CKR_OK.into()
        }
    }

    pub unsafe fn get_mechanism_info(
        &self,
        slot_id: CK_SLOT_ID,
        mechanism_type: CK_MECHANISM_TYPE,
        p_info: CK_MECHANISM_INFO_PTR,
    ) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            if p_info.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            let slot = match Self::slot_arc(state, slot_id) {
                Ok(s) => s,
                Err(rv) => return rv,
            };
            let slot = slot.lock();
            if !B::is_present(&slot.data) {
                return CKR_TOKEN_NOT_PRESENT.into();
            }
            let info = match B::mechanism_info(&slot.data, mechanism_type) {
                Some(i) => i,
                None => return CKR_MECHANISM_INVALID.into(),
            };

            let out = &mut *p_info;
            out.ulMinKeySize = info.min_key_size;
            out.ulMaxKeySize = info.max_key_size;
            out.flags = info.flags;
            CKR_OK.into()
        }
    }

    pub unsafe fn get_token_info(&self, slot_id: CK_SLOT_ID, p_info: CK_TOKEN_INFO_PTR) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            if p_info.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            let slot = match Self::slot_arc(state, slot_id) {
                Ok(s) => s,
                Err(rv) => return rv,
            };
            drop(guard);

            let mut slot = slot.lock();
            let max_sessions = B::max_sessions(&slot.data);
            let tinfo = match B::token_info(&mut slot.data) {
                Some(t) => t,
                None => return CKR_TOKEN_NOT_PRESENT.into(),
            };

            let info = &mut *p_info;
            *info = std::mem::zeroed();
            str_pad(&mut info.label, &tinfo.label);
            str_pad(&mut info.manufacturerID, &tinfo.manufacturer_id);
            str_pad(&mut info.model, &tinfo.model);
            str_pad(&mut info.serialNumber, &tinfo.serial_number);

            info.flags = CKF_RNG as CK_FLAGS
                | CKF_LOGIN_REQUIRED as CK_FLAGS
                | CKF_USER_PIN_INITIALIZED as CK_FLAGS
                | CKF_TOKEN_INITIALIZED as CK_FLAGS
                | tinfo.extra_flags;

            let max = max_sessions
                .map(|n| n as CK_ULONG)
                .unwrap_or(CK_EFFECTIVELY_INFINITE.into());
            info.ulMaxSessionCount = max;
            info.ulMaxRwSessionCount = max;
            for session in slot.sessions.values() {
                if (session.flags & CKF_RW_SESSION as CK_FLAGS) != 0 {
                    info.ulRwSessionCount += 1;
                } else {
                    info.ulSessionCount += 1;
                }
            }
            info.ulMinPinLen = tinfo.min_pin_len;
            info.ulMaxPinLen = tinfo.max_pin_len;
            info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
            info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
            info.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
            info.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
            info.hardwareVersion.major = tinfo.hardware_version.0;
            info.hardwareVersion.minor = tinfo.hardware_version.1;
            info.firmwareVersion.major = tinfo.firmware_version.0;
            info.firmwareVersion.minor = tinfo.firmware_version.1;

            CKR_OK.into()
        }
    }

    pub unsafe fn open_session(
        &self,
        slot_id: CK_SLOT_ID,
        flags: CK_FLAGS,
        _p_application: CK_VOID_PTR,
        _notify: CK_NOTIFY,
        p_session: CK_SESSION_HANDLE_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            if p_session.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            if (flags & CKF_SERIAL_SESSION as CK_FLAGS) == 0 {
                return CKR_SESSION_PARALLEL_NOT_SUPPORTED.into();
            }
            let slot = match Self::slot_arc(state, slot_id) {
                Ok(s) => s,
                Err(rv) => return rv,
            };
            let mut slot_guard = slot.lock();
            if !B::is_present(&slot_guard.data) {
                return CKR_TOKEN_NOT_PRESENT.into();
            }
            if let Some(max) = B::max_sessions(&slot_guard.data) {
                if slot_guard.sessions.len() >= max {
                    return CKR_SESSION_COUNT.into();
                }
            }

            let handle = state.next_session_handle;
            state.next_session_handle += 1;
            state.session_to_slot.insert(handle, slot_id);

            let data = B::new_session_data(&mut slot_guard.data, handle, flags);
            slot_guard.sessions.insert(
                handle,
                Session {
                    handle,
                    flags,
                    find_op: FindOp::default(),
                    data,
                },
            );

            *p_session = handle;
            CKR_OK.into()
        }
    }

    pub unsafe fn close_session(&self, h_session: CK_SESSION_HANDLE) -> CK_RV {
        let mut guard = self.state.lock();
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
        };
        let slot_id = match state.session_to_slot.remove(&h_session) {
            Some(id) => id,
            None => return CKR_SESSION_HANDLE_INVALID.into(),
        };
        let slot = state.slots[slot_id as usize].clone();
        let mut slot_guard = slot.lock();
        slot_guard.sessions.remove(&h_session);
        if slot_guard.sessions.is_empty() {
            slot_guard.login_state = LoginState::Public;
        }
        CKR_OK.into()
    }

    pub unsafe fn close_all_sessions(&self, slot_id: CK_SLOT_ID) -> CK_RV {
        let mut guard = self.state.lock();
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
        };
        let slot = match Self::slot_arc(state, slot_id) {
            Ok(s) => s,
            Err(rv) => return rv,
        };
        let mut slot_guard = slot.lock();
        let handles: Vec<CK_SESSION_HANDLE> = slot_guard.sessions.keys().copied().collect();
        for h in &handles {
            state.session_to_slot.remove(h);
        }
        slot_guard.sessions.clear();
        slot_guard.login_state = LoginState::Public;
        CKR_OK.into()
    }

    pub unsafe fn get_session_info(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_info: CK_SESSION_INFO_PTR,
    ) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            if p_info.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].lock();
            let session = match slot.sessions.get(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let info = &mut *p_info;
            info.slotID = slot_id;
            info.flags = session.flags;
            info.state = compute_state(slot.login_state, session.flags);
            info.ulDeviceError = 0;
            CKR_OK.into()
        }
    }

    pub unsafe fn login(
        &self,
        h_session: CK_SESSION_HANDLE,
        user_type: CK_USER_TYPE,
        p_pin: CK_UTF8CHAR_PTR,
        ul_pin_len: CK_ULONG,
        p_username: CK_UTF8CHAR_PTR,
        ul_username_len: CK_ULONG,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            if !B::is_present(&slot_guard.data) {
                return CKR_TOKEN_NOT_PRESENT.into();
            }

            let pin: &[u8] = if p_pin.is_null() || ul_pin_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_pin as *const u8, ul_pin_len as usize)
            };
            let username: &[u8] = if p_username.is_null() || ul_username_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_username as *const u8, ul_username_len as usize)
            };

            match B::login(&mut slot_guard, user_type, pin, username) {
                Ok(()) => CKR_OK.into(),
                Err(rv) => rv,
            }
        }
    }

    pub unsafe fn logout(&self, h_session: CK_SESSION_HANDLE) -> CK_RV {
        let mut guard = self.state.lock();
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
        };
        let slot_id = match state.session_to_slot.get(&h_session) {
            Some(id) => *id,
            None => return CKR_SESSION_HANDLE_INVALID.into(),
        };
        let slot = state.slots[slot_id as usize].clone();
        let mut slot_guard = slot.lock();
        if !B::is_present(&slot_guard.data) {
            return CKR_TOKEN_NOT_PRESENT.into();
        }
        match B::logout(&mut slot_guard) {
            Ok(()) => CKR_OK.into(),
            Err(rv) => rv,
        }
    }

    pub unsafe fn generate_random(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_random_data: CK_BYTE_PTR,
        ul_random_len: CK_ULONG,
    ) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let slot_guard = slot.lock();

            // Both C modules special-case a zero-length request to succeed
            // without even looking at the pointer (needed by the OpenSC test
            // suite, per their own comments) — matches here too.
            if ul_random_len == 0 {
                return CKR_OK.into();
            }
            if p_random_data.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            let buf =
                std::slice::from_raw_parts_mut(p_random_data as *mut u8, ul_random_len as usize);

            match B::generate_random(&slot_guard, buf) {
                Ok(()) => CKR_OK.into(),
                Err(rv) => rv,
            }
        }
    }

    pub unsafe fn seed_random(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_seed: CK_BYTE_PTR,
        ul_seed_len: CK_ULONG,
    ) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let slot_guard = slot.lock();

            if p_seed.is_null() && ul_seed_len != 0 {
                return CKR_ARGUMENTS_BAD.into();
            }
            let seed: &[u8] = if p_seed.is_null() || ul_seed_len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_seed as *const u8, ul_seed_len as usize)
            };

            match B::seed_random(&slot_guard, seed) {
                Ok(()) => CKR_OK.into(),
                Err(rv) => rv,
            }
        }
    }

    pub unsafe fn find_objects_init(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_template: CK_ATTRIBUTE_PTR,
        ul_count: CK_ULONG,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            if !slot_guard.sessions.contains_key(&h_session) {
                return CKR_SESSION_HANDLE_INVALID.into();
            }
            if slot_guard.sessions[&h_session].find_op.active {
                return CKR_OPERATION_ACTIVE.into();
            }
            if ul_count > 0 && p_template.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let template: &[CK_ATTRIBUTE] = if ul_count == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p_template, ul_count as usize)
            };

            let handles = B::object_handles(&slot_guard);
            let mut matches = Vec::new();
            'outer: for h in handles {
                for attr in template {
                    let value: &[u8] = if attr.pValue.is_null() || attr.ulValueLen == 0 {
                        &[]
                    } else {
                        std::slice::from_raw_parts(
                            attr.pValue as *const u8,
                            attr.ulValueLen as usize,
                        )
                    };

                    match B::get_one_attribute_value(&slot_guard.data, h, attr.type_) {
                        Some(actual) if actual == value => {}
                        _ => continue 'outer,
                    }
                }
                matches.push(h);
            }

            let session = slot_guard.sessions.get_mut(&h_session).unwrap();
            session.find_op = FindOp {
                active: true,
                matches,
                returned_offset: 0,
            };
            CKR_OK.into()
        }
    }

    pub unsafe fn find_objects(
        &self,
        h_session: CK_SESSION_HANDLE,
        p_object: CK_OBJECT_HANDLE_PTR,
        ul_max_object_count: CK_ULONG,
        pul_object_count: CK_ULONG_PTR,
    ) -> CK_RV {
        unsafe {
            let mut guard = self.state.lock();
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let mut slot_guard = slot.lock();
            let session = match slot_guard.sessions.get_mut(&h_session) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            if !session.find_op.active {
                return CKR_OPERATION_NOT_INITIALIZED.into();
            }
            if p_object.is_null() || pul_object_count.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }

            let remaining = &session.find_op.matches[session.find_op.returned_offset..];
            let n = remaining.len().min(ul_max_object_count as usize);
            for (i, h) in remaining[..n].iter().enumerate() {
                *p_object.add(i) = *h;
            }
            session.find_op.returned_offset += n;
            *pul_object_count = n as CK_ULONG;
            CKR_OK.into()
        }
    }

    pub unsafe fn find_objects_final(&self, h_session: CK_SESSION_HANDLE) -> CK_RV {
        let mut guard = self.state.lock();
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
        };
        let slot_id = match state.session_to_slot.get(&h_session) {
            Some(id) => *id,
            None => return CKR_SESSION_HANDLE_INVALID.into(),
        };
        let slot = state.slots[slot_id as usize].clone();
        let mut slot_guard = slot.lock();
        let session = match slot_guard.sessions.get_mut(&h_session) {
            Some(s) => s,
            None => return CKR_SESSION_HANDLE_INVALID.into(),
        };
        if !session.find_op.active {
            return CKR_OPERATION_NOT_INITIALIZED.into();
        }
        session.find_op = FindOp::default();
        CKR_OK.into()
    }

    pub unsafe fn get_attribute_value(
        &self,
        h_session: CK_SESSION_HANDLE,
        h_object: CK_OBJECT_HANDLE,
        p_template: CK_ATTRIBUTE_PTR,
        ul_count: CK_ULONG,
    ) -> CK_RV {
        unsafe {
            let guard = self.state.lock();
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED.into(),
            };
            let slot_id = match state.session_to_slot.get(&h_session) {
                Some(id) => *id,
                None => return CKR_SESSION_HANDLE_INVALID.into(),
            };
            let slot = state.slots[slot_id as usize].clone();
            let slot_guard = slot.lock();
            if !slot_guard.sessions.contains_key(&h_session) {
                return CKR_SESSION_HANDLE_INVALID.into();
            }
            if p_template.is_null() {
                return CKR_ARGUMENTS_BAD.into();
            }
            if !B::object_handles(&slot_guard).contains(&h_object) {
                return CKR_OBJECT_HANDLE_INVALID.into();
            }

            let template = std::slice::from_raw_parts_mut(p_template, ul_count as usize);
            let mut any_invalid = false;
            let mut any_too_small = false;
            for attr in template.iter_mut() {
                match B::get_one_attribute_value(&slot_guard.data, h_object, attr.type_) {
                    None => {
                        attr.ulValueLen = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
                        any_invalid = true;
                    }
                    Some(value) => {
                        if attr.pValue.is_null() {
                            attr.ulValueLen = value.len() as CK_ULONG;
                        } else if (attr.ulValueLen as usize) < value.len() {
                            attr.ulValueLen = CKR_BUFFER_TOO_SMALL as CK_ULONG;
                            any_too_small = true;
                        } else {
                            std::ptr::copy_nonoverlapping(
                                value.as_ptr(),
                                attr.pValue as *mut u8,
                                value.len(),
                            );
                            attr.ulValueLen = value.len() as CK_ULONG;
                        }
                    }
                }
            }

            if any_invalid {
                CKR_ATTRIBUTE_TYPE_INVALID.into()
            } else if any_too_small {
                CKR_BUFFER_TOO_SMALL.into()
            } else {
                CKR_OK.into()
            }
        }
    }
}
