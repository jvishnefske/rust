//! `getrandom(2)`. Keys for `HashMap` don't need to wait for the entropy
//! pool (`GRND_INSECURE`, falling back to a non-blocking read on kernels
//! before 5.6).

use linux_none_rt::sys;

const GRND_NONBLOCK: u32 = 1;
const GRND_INSECURE: u32 = 4;

fn getrandom(mut bytes: &mut [u8], insecure: bool) {
    let mut flags = if insecure { GRND_INSECURE } else { 0 };
    while !bytes.is_empty() {
        match unsafe { sys::getrandom(bytes.as_mut_ptr(), bytes.len(), flags) } {
            Ok(n) => bytes = &mut bytes[n..],
            Err(sys::EINTR) => {}
            Err(sys::EINVAL) if flags == GRND_INSECURE => flags = GRND_NONBLOCK,
            // not enough entropy yet: the keys need not be secret
            Err(sys::EAGAIN) if flags == GRND_NONBLOCK => flags = 0,
            Err(e) => panic!("getrandom failed: {}", sys::strerror(e)),
        }
    }
}

pub fn fill_bytes(bytes: &mut [u8]) {
    getrandom(bytes, false);
}

pub fn hashmap_random_keys() -> (u64, u64) {
    let mut bytes = [0; 16];
    getrandom(&mut bytes, true);
    let k1 = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
    let k2 = u64::from_ne_bytes(bytes[8..].try_into().unwrap());
    (k1, k2)
}
