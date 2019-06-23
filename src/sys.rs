use std::os::raw::c_int;
use std::os::raw::c_void;
use std::os::raw::c_char;

pub type argon2_context = Argon2_Context;
pub type argon2_type = Argon2_type;

pub type allocate_fptr = Option<unsafe extern "C" fn(memory: *mut *mut u8, bytes_to_allocate: usize) -> c_int>;
pub type deallocate_fptr = Option<unsafe extern "C" fn(memory: *mut u8, bytes_to_allocate: usize)>;

pub type Argon2_ErrorCodes  = c_int;
pub type Argon2_type        = c_int;
pub type Argon2_version     = c_int;

#[repr(C)]
pub struct Argon2_Context {
    pub out:        *mut u8,
    pub outlen:     u32,
    pub pwd:        *mut u8,
    pub pwdlen:     u32,
    pub salt:       *mut u8,
    pub saltlen:    u32,
    pub secret:     *mut u8,
    pub secretlen:  u32,
    pub ad:         *mut u8,
    pub adlen:      u32,
    pub t_cost:     u32,
    pub m_cost:     u32,
    pub lanes:      u32,
    pub threads:    u32,
    pub version:    u32,
    pub flags:      u32,

    pub allocate_cbk:   allocate_fptr,
    pub free_cbk:       deallocate_fptr,
}

pub const Argon2_ErrorCodes_ARGON2_OK: Argon2_ErrorCodes = 0;
pub const Argon2_ErrorCodes_ARGON2_OUTPUT_PTR_NULL: Argon2_ErrorCodes = -1;
pub const Argon2_ErrorCodes_ARGON2_OUTPUT_TOO_SHORT: Argon2_ErrorCodes = -2;
pub const Argon2_ErrorCodes_ARGON2_OUTPUT_TOO_LONG: Argon2_ErrorCodes = -3;
pub const Argon2_ErrorCodes_ARGON2_PWD_TOO_SHORT: Argon2_ErrorCodes = -4;
pub const Argon2_ErrorCodes_ARGON2_PWD_TOO_LONG: Argon2_ErrorCodes = -5;
pub const Argon2_ErrorCodes_ARGON2_SALT_TOO_SHORT: Argon2_ErrorCodes = -6;
pub const Argon2_ErrorCodes_ARGON2_SALT_TOO_LONG: Argon2_ErrorCodes = -7;
pub const Argon2_ErrorCodes_ARGON2_AD_TOO_SHORT: Argon2_ErrorCodes = -8;
pub const Argon2_ErrorCodes_ARGON2_AD_TOO_LONG: Argon2_ErrorCodes = -9;
pub const Argon2_ErrorCodes_ARGON2_SECRET_TOO_SHORT: Argon2_ErrorCodes = -10;
pub const Argon2_ErrorCodes_ARGON2_SECRET_TOO_LONG: Argon2_ErrorCodes = -11;
pub const Argon2_ErrorCodes_ARGON2_TIME_TOO_SMALL: Argon2_ErrorCodes = -12;
pub const Argon2_ErrorCodes_ARGON2_TIME_TOO_LARGE: Argon2_ErrorCodes = -13;
pub const Argon2_ErrorCodes_ARGON2_MEMORY_TOO_LITTLE: Argon2_ErrorCodes = -14;
pub const Argon2_ErrorCodes_ARGON2_MEMORY_TOO_MUCH: Argon2_ErrorCodes = -15;
pub const Argon2_ErrorCodes_ARGON2_LANES_TOO_FEW: Argon2_ErrorCodes = -16;
pub const Argon2_ErrorCodes_ARGON2_LANES_TOO_MANY: Argon2_ErrorCodes = -17;
pub const Argon2_ErrorCodes_ARGON2_PWD_PTR_MISMATCH: Argon2_ErrorCodes = -18;
pub const Argon2_ErrorCodes_ARGON2_SALT_PTR_MISMATCH: Argon2_ErrorCodes = -19;
pub const Argon2_ErrorCodes_ARGON2_SECRET_PTR_MISMATCH: Argon2_ErrorCodes = -20;
pub const Argon2_ErrorCodes_ARGON2_AD_PTR_MISMATCH: Argon2_ErrorCodes = -21;
pub const Argon2_ErrorCodes_ARGON2_MEMORY_ALLOCATION_ERROR: Argon2_ErrorCodes = -22;
pub const Argon2_ErrorCodes_ARGON2_FREE_MEMORY_CBK_NULL: Argon2_ErrorCodes = -23;
pub const Argon2_ErrorCodes_ARGON2_ALLOCATE_MEMORY_CBK_NULL: Argon2_ErrorCodes = -24;
pub const Argon2_ErrorCodes_ARGON2_INCORRECT_PARAMETER: Argon2_ErrorCodes = -25;
pub const Argon2_ErrorCodes_ARGON2_INCORRECT_TYPE: Argon2_ErrorCodes = -26;
pub const Argon2_ErrorCodes_ARGON2_OUT_PTR_MISMATCH: Argon2_ErrorCodes = -27;
pub const Argon2_ErrorCodes_ARGON2_THREADS_TOO_FEW: Argon2_ErrorCodes = -28;
pub const Argon2_ErrorCodes_ARGON2_THREADS_TOO_MANY: Argon2_ErrorCodes = -29;
pub const Argon2_ErrorCodes_ARGON2_MISSING_ARGS: Argon2_ErrorCodes = -30;
pub const Argon2_ErrorCodes_ARGON2_ENCODING_FAIL: Argon2_ErrorCodes = -31;
pub const Argon2_ErrorCodes_ARGON2_DECODING_FAIL: Argon2_ErrorCodes = -32;
pub const Argon2_ErrorCodes_ARGON2_THREAD_FAIL: Argon2_ErrorCodes = -33;
pub const Argon2_ErrorCodes_ARGON2_DECODING_LENGTH_FAIL: Argon2_ErrorCodes = -34;
pub const Argon2_ErrorCodes_ARGON2_VERIFY_MISMATCH: Argon2_ErrorCodes = -35;

pub const Argon2_type_Argon2_d: Argon2_type     = 0;
pub const Argon2_type_Argon2_i: Argon2_type     = 1;
pub const Argon2_type_Argon2_id: Argon2_type    = 2;

pub const Argon2_version_ARGON2_VERSION_10: Argon2_version = 0x10;
pub const Argon2_version_ARGON2_VERSION_13: Argon2_version = 0x13;
pub const Argon2_version_ARGON2_VERSION_NUMBER: Argon2_version = Argon2_version_ARGON2_VERSION_13;

extern "C" {
    pub fn argon2_ctx(context: *mut argon2_context, type_: argon2_type) -> c_int;

    pub fn argon2i_hash_encoded(t_cost: u32, m_cost: u32, parallelism: u32, pwd: *const c_void, pwdlen: usize, salt: *const c_void, saltlen: usize, hashlen: usize, encoded: *mut c_char, encodedlen: usize) -> c_int;

    pub fn argon2i_hash_raw(t_cost: u32, m_cost: u32, parallelism: u32, pwd: *const c_void, pwdlen: usize, salt: *const c_void, saltlen: usize, hash: *mut c_void, hashlen: usize) -> c_int;

    pub fn argon2d_hash_encoded(t_cost: u32, m_cost: u32, parallelism: u32, pwd: *const c_void, pwdlen: usize, salt: *const c_void, saltlen: usize, hashlen: usize, encoded: *mut c_char, encodedlen: usize) -> c_int;

    pub fn argon2d_hash_raw(t_cost: u32, m_cost: u32, parallelism: u32, pwd: *const c_void, pwdlen: usize, salt: *const c_void, saltlen: usize, hash: *mut c_void, hashlen: usize) -> c_int;

    pub fn argon2id_hash_encoded(t_cost: u32, m_cost: u32, parallelism: u32, pwd: *const c_void, pwdlen: usize, salt: *const c_void, saltlen: usize, hashlen: usize, encoded: *mut c_char, encodedlen: usize) -> c_int;

    pub fn argon2id_hash_raw(t_cost: u32, m_cost: u32, parallelism: u32, pwd: *const c_void, pwdlen: usize, salt: *const c_void, saltlen: usize, hash: *mut c_void, hashlen: usize) -> c_int;

    pub fn argon2_hash(t_cost: u32, m_cost: u32, parallelism: u32, pwd: *const c_void, pwdlen: usize, salt: *const c_void, saltlen: usize, hash: *mut c_void, hashlen: usize, encoded: *mut c_char, encodedlen: usize, type_: argon2_type, version: u32) -> c_int;

    pub fn argon2i_verify(encoded: *const c_char, pwd: *const c_void, pwdlen: usize) -> c_int;

    pub fn argon2d_verify(encoded: *const c_char, pwd: *const c_void, pwdlen: usize) -> c_int;

    pub fn argon2id_verify(encoded: *const c_char, pwd: *const c_void, pwdlen: usize) -> c_int;

    pub fn argon2_verify(encoded: *const c_char, pwd: *const c_void, pwdlen: usize, type_: argon2_type) -> c_int;

    pub fn argon2d_ctx(context: *mut argon2_context) -> c_int;

    pub fn argon2i_ctx(context: *mut argon2_context) -> c_int;

    pub fn argon2id_ctx(context: *mut argon2_context) -> c_int;

    pub fn argon2d_verify_ctx(context: *mut argon2_context, hash: *const c_char) -> c_int;

    pub fn argon2i_verify_ctx(context: *mut argon2_context, hash: *const c_char) -> c_int;

    pub fn argon2id_verify_ctx(context: *mut argon2_context, hash: *const c_char) -> c_int;

    pub fn argon2_verify_ctx(context: *mut argon2_context, hash: *const c_char, type_: argon2_type) -> c_int;

    pub fn argon2_error_message( error_code: c_int) -> *const c_char;

    pub fn argon2_encodedlen(t_cost: u32, m_cost: u32, parallelism: u32, saltlen: u32, hashlen: u32, type_: argon2_type) -> usize;

    pub fn argon2_type2string(type_: argon2_type, uppercase: c_int) -> *const c_char;
}
