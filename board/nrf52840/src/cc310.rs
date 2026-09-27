use core::ffi::{c_char, c_void};

#[cfg(all(feature = "cc310-rsa", feature = "engine-jcvm"))]
const RSA_ALLOC_LIMIT: usize = 8192;

#[cfg(all(feature = "cc310-rsa", feature = "engine-jcvm"))]
#[no_mangle]
unsafe extern "C" fn mbedtls_calloc(count: usize, size: usize) -> *mut c_void {
    use alloc::alloc::alloc_zeroed;
    use core::alloc::Layout;

    let Some(bytes) = count.checked_mul(size) else {
        return core::ptr::null_mut();
    };
    let bytes = bytes.max(1);
    if bytes > RSA_ALLOC_LIMIT {
        return core::ptr::null_mut();
    }
    let Some(total) = bytes.checked_add(8) else {
        return core::ptr::null_mut();
    };
    let Ok(layout) = Layout::from_size_align(total, 8) else {
        return core::ptr::null_mut();
    };
    let base = unsafe { alloc_zeroed(layout) };
    if base.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { base.cast::<usize>().write(bytes) };
    unsafe { base.add(8).cast() }
}

#[cfg(all(feature = "cc310-rsa", feature = "engine-jcvm"))]
#[no_mangle]
unsafe extern "C" fn mbedtls_free(pointer: *mut c_void) {
    use alloc::alloc::dealloc;
    use core::alloc::Layout;

    if pointer.is_null() {
        return;
    }
    let base = unsafe { pointer.cast::<u8>().sub(8) };
    let bytes = unsafe { base.cast::<usize>().read() };
    if bytes == 0 || bytes > RSA_ALLOC_LIMIT {
        return;
    }
    let Ok(layout) = Layout::from_size_align(bytes + 8, 8) else {
        return;
    };
    unsafe {
        core::ptr::write_bytes(base, 0, bytes + 8);
        dealloc(base, layout);
    }
}

#[repr(C)]
struct AbortApis {
    handle: *mut c_void,
    abort: unsafe extern "C" fn(*const c_char),
}

unsafe impl Sync for AbortApis {}

unsafe extern "C" fn abort(_reason: *const c_char) {
    #[cfg(feature = "development-recovery")]
    super::enter_uf2();
    #[cfg(not(feature = "development-recovery"))]
    cortex_m::peripheral::SCB::sys_reset()
}

static ABORT_APIS: AbortApis = AbortApis {
    handle: core::ptr::null_mut(),
    abort,
};

unsafe extern "C" {
    #[cfg(feature = "cc310-p256")]
    pub(super) fn microcard_cc310_sha256_stream(
        state: *mut u8,
        state_size: usize,
        input: *const u8,
        input_size: usize,
        output: *mut u8,
    ) -> i32;
    #[cfg(feature = "cc310-p256")]
    pub(super) fn microcard_cc310_sha224_stream(
        state: *mut u8,
        state_size: usize,
        input: *const u8,
        input_size: usize,
        output: *mut u8,
    ) -> i32;
    #[cfg(feature = "cc310-p256")]
    pub(super) fn microcard_cc310_sha1_stream(
        state: *mut u8,
        state_size: usize,
        input: *const u8,
        input_size: usize,
        output: *mut u8,
    ) -> i32;
    fn nrf_cc3xx_platform_set_abort(apis: *const AbortApis);
    #[cfg(feature = "cc310-entropy")]
    fn nrf_cc3xx_platform_init() -> i32;
    #[cfg(not(feature = "cc310-entropy"))]
    fn nrf_cc3xx_platform_init_no_rng() -> i32;
    #[cfg(feature = "cc310-entropy")]
    fn nrf_cc3xx_platform_entropy_get(
        output: *mut u8,
        length: usize,
        output_length: *mut usize,
    ) -> i32;
    fn nrf_cc3xx_platform_sha256_hash(
        ram_buffer: *mut c_void,
        ram_buffer_size: usize,
        data: *mut c_void,
        length: usize,
        output: *mut c_void,
    ) -> i32;
    #[cfg(feature = "cc310-cmac")]
    fn microcard_cc310_cmac_begin(
        storage: *mut c_void,
        storage_size: usize,
        key: *const u8,
        key_size: usize,
    ) -> i32;
    #[cfg(any(feature = "cc310-cmac", feature = "cc310-hmac"))]
    fn microcard_cc310_mac_update(
        storage: *mut c_void,
        storage_size: usize,
        input: *const u8,
        input_size: usize,
    ) -> i32;
    #[cfg(feature = "cc310-cmac")]
    fn microcard_cc310_cmac_finish(
        storage: *mut c_void,
        storage_size: usize,
        output: *mut u8,
        output_size: usize,
    ) -> i32;
    #[cfg(feature = "cc310-hmac")]
    fn microcard_cc310_hmac_sha256_begin(
        storage: *mut c_void,
        storage_size: usize,
        key: *const u8,
        key_size: usize,
    ) -> i32;
    #[cfg(feature = "cc310-hmac")]
    fn microcard_cc310_hmac_sha256_finish(
        storage: *mut c_void,
        storage_size: usize,
        output: *mut u8,
        output_size: usize,
    ) -> i32;
    #[cfg(feature = "cc310-aes")]
    fn microcard_cc310_aes128_encrypt_block(
        key: *const u8,
        key_size: usize,
        input: *const u8,
        input_size: usize,
        output: *mut u8,
        output_size: usize,
    ) -> i32;
    #[cfg(feature = "cc310-aes")]
    fn microcard_cc310_aes128_cbc_in_place(
        key: *const u8,
        key_size: usize,
        iv: *const u8,
        iv_size: usize,
        buffer: *mut u8,
        buffer_size: usize,
        encrypt: i32,
    ) -> i32;
    #[cfg(feature = "cc310-ctr")]
    fn microcard_cc310_aes128_ctr_in_place(
        key: *const u8,
        key_size: usize,
        iv: *const u8,
        iv_size: usize,
        buffer: *mut u8,
        buffer_size: usize,
    ) -> i32;
    #[cfg(feature = "cc310-ccm")]
    fn microcard_cc310_aes128_ccm_encrypt(
        key: *const u8,
        key_size: usize,
        nonce: *const u8,
        nonce_size: usize,
        aad: *const u8,
        aad_size: usize,
        plaintext: *const u8,
        plaintext_size: usize,
        ciphertext: *mut u8,
        ciphertext_size: usize,
    ) -> i32;
    #[cfg(feature = "cc310-ccm")]
    fn microcard_cc310_aes128_ccm_decrypt(
        key: *const u8,
        key_size: usize,
        nonce: *const u8,
        nonce_size: usize,
        aad: *const u8,
        aad_size: usize,
        ciphertext: *const u8,
        ciphertext_size: usize,
        plaintext: *mut u8,
        plaintext_size: usize,
    ) -> i32;
    #[cfg(feature = "cc310-p256")]
    fn microcard_cc310_p256_public_key(
        private_key: *const u8,
        private_key_size: usize,
        public_key: *mut u8,
        public_key_size: usize,
    ) -> i32;
    #[cfg(feature = "cc310-p256")]
    fn microcard_cc310_p256_sign_hash(
        private_key: *const u8,
        private_key_size: usize,
        hash: *const u8,
        hash_size: usize,
        signature: *mut u8,
        signature_size: usize,
    ) -> i32;
    #[cfg(feature = "cc310-p256")]
    fn microcard_cc310_p256_verify_hash(
        public_key: *const u8,
        public_key_size: usize,
        hash: *const u8,
        hash_size: usize,
        signature: *const u8,
        signature_size: usize,
    ) -> i32;
    #[cfg(feature = "cc310-p256")]
    fn microcard_cc310_p256_ecdh(
        private_key: *const u8,
        private_key_size: usize,
        peer_public_key: *const u8,
        peer_public_key_size: usize,
        secret: *mut u8,
        secret_size: usize,
    ) -> i32;
    #[cfg(all(feature = "cc310-rsa", feature = "engine-jcvm"))]
    fn microcard_cc310_rsa_generate_key_pair(
        key_bits: usize,
        private_der: *mut u8,
        private_capacity: usize,
        private_length: *mut usize,
        public_der: *mut u8,
        public_capacity: usize,
        public_length: *mut usize,
    ) -> i32;
    #[cfg(all(feature = "cc310-rsa", feature = "engine-jcvm"))]
    fn microcard_cc310_rsa_pkcs1v15_sha256_sign(
        private_der: *const u8,
        private_der_size: usize,
        key_bits: usize,
        hash: *const u8,
        hash_size: usize,
        signature: *mut u8,
        signature_size: usize,
    ) -> i32;
    #[cfg(all(feature = "cc310-rsa", feature = "engine-jcvm"))]
    fn microcard_cc310_rsa_pkcs1v15_sha256_verify(
        public_der: *const u8,
        public_der_size: usize,
        key_bits: usize,
        hash: *const u8,
        hash_size: usize,
        signature: *const u8,
        signature_size: usize,
    ) -> i32;
}

#[no_mangle]
extern "C" fn nrf_cc3xx_platform_abort_init() {
    unsafe { nrf_cc3xx_platform_set_abort(&ABORT_APIS) }
}

#[no_mangle]
extern "C" fn nrf_cc3xx_platform_mutex_init() {}

#[repr(align(4))]
struct WordAligned<T>(T);

#[cfg(any(feature = "cc310-cmac", feature = "cc310-hmac"))]
#[repr(align(8))]
struct MacState([u8; 544]);

pub(super) fn initialize() -> bool {
    nrf_cc3xx_platform_abort_init();
    nrf_cc3xx_platform_mutex_init();
    #[cfg(feature = "cc310-entropy")]
    unsafe {
        nrf_cc3xx_platform_init() == 0
    }
    #[cfg(not(feature = "cc310-entropy"))]
    unsafe {
        nrf_cc3xx_platform_init_no_rng() == 0
    }
}

pub(super) fn sha256(data: &[u8], output: &mut [u8; 32]) -> bool {
    let mut dma_scratch = WordAligned([0u8; 16]);
    let mut result = [0u8; 32];
    let status = unsafe {
        nrf_cc3xx_platform_sha256_hash(
            dma_scratch.0.as_mut_ptr().cast(),
            dma_scratch.0.len(),
            data.as_ptr().cast_mut().cast(),
            data.len(),
            result.as_mut_ptr().cast(),
        )
    };
    dma_scratch.0.fill(0);
    if status != 0 {
        result.fill(0);
        return false;
    }
    *output = result;
    result.fill(0);
    true
}

#[cfg(feature = "cc310-entropy")]
pub(super) fn fill_entropy(output: &mut [u8]) -> bool {
    if output.is_empty() {
        return true;
    }
    let mut written = 0usize;
    let status =
        unsafe { nrf_cc3xx_platform_entropy_get(output.as_mut_ptr(), output.len(), &mut written) };
    if status != 0 || written != output.len() {
        output.fill(0);
        return false;
    }
    true
}

#[cfg(feature = "cc310-cmac")]
pub(super) fn aes_cmac_parts(key: &[u8; 16], parts: &[&[u8]], output: &mut [u8; 16]) -> bool {
    let mut state = MacState([0; 544]);
    let mut result = [0; 16];
    let state_pointer = state.0.as_mut_ptr().cast();
    let mut status = unsafe {
        microcard_cc310_cmac_begin(state_pointer, state.0.len(), key.as_ptr(), key.len())
    };
    for part in parts {
        if status != 0 {
            break;
        }
        status = unsafe {
            microcard_cc310_mac_update(state_pointer, state.0.len(), part.as_ptr(), part.len())
        };
    }
    if status == 0 {
        status = unsafe {
            microcard_cc310_cmac_finish(
                state_pointer,
                state.0.len(),
                result.as_mut_ptr(),
                result.len(),
            )
        };
    }
    state.0.fill(0);
    if status != 0 {
        result.fill(0);
        return false;
    }
    *output = result;
    result.fill(0);
    true
}

#[cfg(feature = "cc310-hmac")]
pub(super) fn hmac_sha256(key: &[u8], data: &[u8], output: &mut [u8; 32]) -> bool {
    let mut state = MacState([0; 544]);
    let mut result = [0; 32];
    let state_pointer = state.0.as_mut_ptr().cast();
    let mut status = unsafe {
        microcard_cc310_hmac_sha256_begin(state_pointer, state.0.len(), key.as_ptr(), key.len())
    };
    if status == 0 {
        status = unsafe {
            microcard_cc310_mac_update(state_pointer, state.0.len(), data.as_ptr(), data.len())
        };
    }
    if status == 0 {
        status = unsafe {
            microcard_cc310_hmac_sha256_finish(
                state_pointer,
                state.0.len(),
                result.as_mut_ptr(),
                result.len(),
            )
        };
    }
    state.0.fill(0);
    if status != 0 {
        result.fill(0);
        return false;
    }
    *output = result;
    result.fill(0);
    true
}

#[cfg(feature = "cc310-aes")]
pub(super) fn aes128_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) -> bool {
    let mut result = [0; 16];
    let status = unsafe {
        microcard_cc310_aes128_encrypt_block(
            key.as_ptr(),
            key.len(),
            block.as_ptr(),
            block.len(),
            result.as_mut_ptr(),
            result.len(),
        )
    };
    if status != 0 {
        result.fill(0);
        return false;
    }
    *block = result;
    result.fill(0);
    true
}

#[cfg(feature = "cc310-aes")]
pub(super) fn aes128_cbc_in_place(
    key: &[u8; 16],
    iv: &[u8; 16],
    buffer: &mut [u8],
    encrypt: bool,
) -> bool {
    let status = unsafe {
        microcard_cc310_aes128_cbc_in_place(
            key.as_ptr(),
            key.len(),
            iv.as_ptr(),
            iv.len(),
            buffer.as_mut_ptr(),
            buffer.len(),
            i32::from(encrypt),
        )
    };
    if status != 0 {
        buffer.fill(0);
        return false;
    }
    true
}

#[cfg(feature = "cc310-ctr")]
pub(super) fn aes128_ctr_in_place(key: &[u8; 16], iv: &[u8; 16], buffer: &mut [u8]) -> bool {
    if buffer.is_empty() {
        return true;
    }
    let status = unsafe {
        microcard_cc310_aes128_ctr_in_place(
            key.as_ptr(),
            key.len(),
            iv.as_ptr(),
            iv.len(),
            buffer.as_mut_ptr(),
            buffer.len(),
        )
    };
    if status != 0 {
        buffer.fill(0);
        return false;
    }
    true
}

#[cfg(feature = "cc310-ccm")]
pub(super) fn aes128_ccm_encrypt(
    key: &[u8; 16],
    nonce: &[u8; 13],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> i32 {
    unsafe {
        microcard_cc310_aes128_ccm_encrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
        )
    }
}

#[cfg(feature = "cc310-ccm")]
pub(super) fn aes128_ccm_encrypt_in_place(
    key: &[u8; 16],
    nonce: &[u8; 13],
    aad: &[u8],
    buffer: &mut [u8],
) -> i32 {
    let Some(length) = buffer.len().checked_sub(16) else {
        return -1;
    };
    // Pass raw pointers through FFI, never overlapping Rust references.
    let pointer = buffer.as_mut_ptr();
    unsafe {
        microcard_cc310_aes128_ccm_encrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            pointer,
            length,
            pointer,
            buffer.len(),
        )
    }
}

#[cfg(feature = "cc310-ccm")]
pub(super) fn aes128_ccm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 13],
    aad: &[u8],
    ciphertext: &[u8],
    plaintext: &mut [u8],
) -> i32 {
    unsafe {
        microcard_cc310_aes128_ccm_decrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            plaintext.as_mut_ptr(),
            plaintext.len(),
        )
    }
}

#[cfg(feature = "cc310-ccm")]
pub(super) fn aes128_ccm_decrypt_in_place(
    key: &[u8; 16],
    nonce: &[u8; 13],
    aad: &[u8],
    ciphertext: &mut [u8],
) -> i32 {
    let Some(length) = ciphertext.len().checked_sub(16) else {
        return 1;
    };
    // Pass one buffer through FFI without constructing aliased Rust references.
    let pointer = ciphertext.as_mut_ptr();
    unsafe {
        microcard_cc310_aes128_ccm_decrypt(
            key.as_ptr(),
            key.len(),
            nonce.as_ptr(),
            nonce.len(),
            aad.as_ptr(),
            aad.len(),
            pointer,
            ciphertext.len(),
            pointer,
            length,
        )
    }
}

#[cfg(feature = "cc310-p256")]
pub(super) fn p256_public_key(private_key: &[u8; 32], output: &mut [u8; 65]) -> bool {
    unsafe {
        microcard_cc310_p256_public_key(
            private_key.as_ptr(),
            private_key.len(),
            output.as_mut_ptr(),
            output.len(),
        ) == 0
    }
}

#[cfg(feature = "cc310-p256")]
pub(super) fn p256_sign_hash(
    private_key: &[u8; 32],
    hash: &[u8; 32],
    output: &mut [u8; 64],
) -> bool {
    unsafe {
        microcard_cc310_p256_sign_hash(
            private_key.as_ptr(),
            private_key.len(),
            hash.as_ptr(),
            hash.len(),
            output.as_mut_ptr(),
            output.len(),
        ) == 0
    }
}

#[cfg(feature = "cc310-p256")]
pub(super) fn p256_verify_hash(public_key: &[u8], hash: &[u8; 32], signature: &[u8]) -> i32 {
    unsafe {
        microcard_cc310_p256_verify_hash(
            public_key.as_ptr(),
            public_key.len(),
            hash.as_ptr(),
            hash.len(),
            signature.as_ptr(),
            signature.len(),
        )
    }
}

#[cfg(feature = "cc310-p256")]
pub(super) fn p256_ecdh(
    private_key: &[u8; 32],
    peer_public_key: &[u8],
    output: &mut [u8; 32],
) -> i32 {
    unsafe {
        microcard_cc310_p256_ecdh(
            private_key.as_ptr(),
            private_key.len(),
            peer_public_key.as_ptr(),
            peer_public_key.len(),
            output.as_mut_ptr(),
            output.len(),
        )
    }
}

#[cfg(all(feature = "cc310-rsa", feature = "engine-jcvm"))]
pub(super) fn rsa_generate_key_pair(
    key_bits: usize,
    private_der: &mut [u8],
    public_der: &mut [u8],
) -> Option<(usize, usize)> {
    private_der.fill(0);
    public_der.fill(0);
    let mut private_len = 0;
    let mut public_len = 0;
    let status = unsafe {
        microcard_cc310_rsa_generate_key_pair(
            key_bits, private_der.as_mut_ptr(), private_der.len(), &mut private_len,
            public_der.as_mut_ptr(), public_der.len(), &mut public_len,
        )
    };
    if status != 0 || private_len > private_der.len() || public_len > public_der.len() {
        private_der.fill(0);
        public_der.fill(0);
        return None;
    }
    Some((private_len, public_len))
}

#[cfg(all(feature = "cc310-rsa", feature = "engine-jcvm"))]
pub(super) fn rsa_pkcs1v15_sha256_sign(
    private_der: &[u8],
    key_bits: usize,
    hash: &[u8; 32],
    signature: &mut [u8],
) -> bool {
    let status = unsafe {
        microcard_cc310_rsa_pkcs1v15_sha256_sign(
            private_der.as_ptr(),
            private_der.len(),
            key_bits,
            hash.as_ptr(),
            hash.len(),
            signature.as_mut_ptr(),
            signature.len(),
        )
    };
    if status != 0 {
        signature.fill(0);
        return false;
    }
    true
}

#[cfg(all(feature = "cc310-rsa", feature = "engine-jcvm"))]
pub(super) fn rsa_pkcs1v15_sha256_verify(
    public_der: &[u8],
    key_bits: usize,
    hash: &[u8; 32],
    signature: &[u8],
) -> i32 {
    unsafe {
        microcard_cc310_rsa_pkcs1v15_sha256_verify(
            public_der.as_ptr(),
            public_der.len(),
            key_bits,
            hash.as_ptr(),
            hash.len(),
            signature.as_ptr(),
            signature.len(),
        )
    }
}
