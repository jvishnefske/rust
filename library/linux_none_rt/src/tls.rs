//! ELF thread-local storage for a static, non-PIE executable.
//!
//! The linker resolves `#[thread_local]` accesses to fixed offsets from the
//! thread pointer (the local-exec model), so each thread needs a copy of the
//! `PT_TLS` image placed exactly where those offsets expect it:
//!
//! - x86_64 (variant II): the block ends just below the thread pointer, and
//!   the word at the thread pointer points to itself (`fs:0`).
//! - aarch64 (variant I): the thread pointer is followed by a 16-byte TCB,
//!   then the block.
//!
//! The offsets are those lld computes (`getTlsTpOffset`), which also fix the
//! block's alignment relative to the thread pointer.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::elf::{PT_TLS, Phdr};

#[cfg(linux_none)]
use crate::sys;

/// Bytes of TCB at the thread pointer that the runtime owns: x86_64's
/// self-pointer, aarch64's two reserved words.
const TCB_SIZE: usize = 16;

/// The `PT_TLS` segment: initialized data (`.tdata`) followed by zeroed
/// data (`.tbss`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Image {
    pub addr: usize,
    pub filesz: usize,
    pub memsz: usize,
    pub align: usize,
}

impl Image {
    pub const EMPTY: Image = Image { addr: 0, filesz: 0, memsz: 0, align: 1 };
}

static ADDR: AtomicUsize = AtomicUsize::new(0);
static FILESZ: AtomicUsize = AtomicUsize::new(0);
static MEMSZ: AtomicUsize = AtomicUsize::new(0);
static ALIGN: AtomicUsize = AtomicUsize::new(1);

/// The executable's TLS image, as recorded by [`init_main_thread`].
pub fn image() -> Image {
    Image {
        addr: ADDR.load(Ordering::Relaxed),
        filesz: FILESZ.load(Ordering::Relaxed),
        memsz: MEMSZ.load(Ordering::Relaxed),
        align: ALIGN.load(Ordering::Relaxed),
    }
}

/// Find `PT_TLS` among the program headers.
#[cfg_attr(not(linux_none), allow(dead_code))]
fn find_image(phdrs: &[Phdr]) -> Image {
    for h in phdrs {
        if h.p_type == PT_TLS {
            // a non-PIE executable is not relocated: p_vaddr is the address
            return Image {
                addr: h.p_vaddr as usize,
                filesz: h.p_filesz as usize,
                memsz: h.p_memsz as usize,
                align: (h.p_align as usize).max(1),
            };
        }
    }
    Image::EMPTY
}

/// Where a thread's TLS goes inside an area of [`Layout::size`] bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// alignment of the area and of the thread pointer
    pub align: usize,
    /// bytes to reserve (before aligning the area's start)
    pub size: usize,
    /// offset of the thread pointer from the (aligned) area start
    pub tp: usize,
    /// offset of the TLS block from the (aligned) area start
    pub block: usize,
}

const fn round_up(n: usize, to: usize) -> usize {
    (n + to - 1) & !(to - 1)
}

impl Layout {
    /// Lay out `img` (alignment a power of two) for the current architecture.
    pub const fn new(img: &Image) -> Layout {
        let align = if img.align > TCB_SIZE { img.align } else { TCB_SIZE };
        if cfg!(target_arch = "x86_64") {
            // lld: tp - memsz - ((-vaddr - memsz) & (align - 1))
            let gap = (0usize.wrapping_sub(img.addr).wrapping_sub(img.memsz)) & (img.align - 1);
            let tp = round_up(img.memsz + gap, align);
            Layout { align, size: tp + TCB_SIZE, tp, block: tp - img.memsz - gap }
        } else {
            // lld: tp + 16 + ((vaddr - 16) & (align - 1))
            let gap = img.addr.wrapping_sub(TCB_SIZE) & (img.align - 1);
            Layout { align, size: TCB_SIZE + gap + img.memsz, tp: 0, block: TCB_SIZE + gap }
        }
    }

    /// Bytes to reserve for an area whose start is not yet aligned.
    pub const fn reserve(&self) -> usize {
        self.size + self.align - 1
    }
}

/// Initialize a thread's TLS in `area` (at least [`Layout::reserve`] bytes
/// for the current image) and return the value for its thread pointer.
///
/// # Safety
/// `area` must be writable for `reserve()` bytes and not otherwise in use.
pub unsafe fn init_area(area: *mut u8) -> usize {
    let img = image();
    let l = Layout::new(&img);
    let base = round_up(area as usize, l.align);
    unsafe {
        let block = (base + l.block) as *mut u8;
        core::ptr::copy_nonoverlapping(img.addr as *const u8, block, img.filesz);
        core::ptr::write_bytes(block.add(img.filesz), 0, img.memsz - img.filesz);
        let tp = base + l.tp;
        let tcb = tp as *mut usize;
        if cfg!(target_arch = "x86_64") {
            *tcb = tp;
        } else {
            *tcb = 0;
        }
        *tcb.add(THREAD_WORD) = 0;
        tp
    }
}

/// The TCB word (after x86_64's self-pointer, the second of aarch64's
/// reserved pair) where [`crate::thread`] keeps the thread's control block:
/// 0 on the main thread.
const THREAD_WORD: usize = 1;

/// Set the [`THREAD_WORD`] of the TCB at `tp`, as returned by [`init_area`].
///
/// # Safety
/// `tp` must be a thread pointer from [`init_area`].
pub(crate) unsafe fn set_thread_word(tp: usize, v: usize) {
    unsafe { *(tp as *mut usize).add(THREAD_WORD) = v };
}

/// The calling thread's [`THREAD_WORD`] (async-signal-safe).
#[cfg(linux_none)]
pub(crate) fn thread_word() -> usize {
    unsafe { *(crate::arch::thread_pointer() as *const usize).add(THREAD_WORD) }
}

/// Record the TLS image and give the main thread its TLS.
#[cfg(linux_none)]
pub(crate) unsafe fn init_main_thread() {
    let img = find_image(crate::elf::program_headers());
    ADDR.store(img.addr, Ordering::Relaxed);
    FILESZ.store(img.filesz, Ordering::Relaxed);
    MEMSZ.store(img.memsz, Ordering::Relaxed);
    ALIGN.store(img.align, Ordering::Relaxed);

    let len = Layout::new(&img).reserve();
    let area = unsafe {
        sys::mmap(0, len, sys::PROT_READ | sys::PROT_WRITE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS, -1, 0)
    };
    let Ok(area) = area else {
        crate::start::write_stderr(b"fatal: cannot allocate the main thread's TLS\n");
        sys::exit_group(127);
    };
    unsafe { crate::arch::set_thread_pointer(init_area(area as *mut u8)) };
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// The block fits in the area, does not overlap the TCB, and sits at the
    /// offset from the thread pointer that the linker assumed.
    #[kani::proof]
    fn layout_matches_linker() {
        let align = 1usize << kani::any_where(|&k: &u32| k <= 12);
        let memsz: usize = kani::any_where(|&m| m <= 1 << 20);
        let filesz: usize = kani::any_where(|&f| f <= memsz);
        let addr: usize = kani::any_where(|&a| a <= 1 << 40);
        let img = Image { addr, filesz, memsz, align };
        let l = Layout::new(&img);
        assert!(l.align.is_power_of_two() && l.align >= align && l.align >= TCB_SIZE);
        assert!(l.tp % l.align == 0);
        assert!(l.block + memsz <= l.size && l.tp + TCB_SIZE <= l.size);
        // block start ≡ p_vaddr (mod p_align), given an aligned area start
        assert!(l.block % align == addr % align);
        if cfg!(target_arch = "x86_64") {
            assert!(l.block + memsz <= l.tp);
            let gap = (0usize.wrapping_sub(addr).wrapping_sub(memsz)) & (align - 1);
            assert!(l.tp - l.block == memsz + gap);
        } else {
            assert!(l.block >= l.tp + TCB_SIZE);
            assert!(l.block - l.tp == TCB_SIZE + (addr.wrapping_sub(TCB_SIZE) & (align - 1)));
        }
    }
}
