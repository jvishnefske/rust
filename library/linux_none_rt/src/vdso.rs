//! The vDSO: the small shared object the kernel maps into every process
//! (`AT_SYSINFO_EHDR`), whose `clock_gettime` reads the clocks from a shared
//! page instead of entering the kernel.
//!
//! [`init`] finds it at startup and resolves `clock_gettime`;
//! [`crate::sys::clock_gettime`] calls it, or makes the syscall when there
//! is no vDSO (qemu-user, `vdso=0`) or it fails.
//!
//! The parser ([`image_size`], [`lookup`]) works on a byte slice, checks
//! every offset against it and never panics, whatever the bytes. It follows
//! the dynamic section to the symbol, string, hash (`DT_HASH` or
//! `DT_GNU_HASH`) and version (`DT_VERSYM`/`DT_VERDEF`) tables, as the
//! kernel's `tools/testing/selftests/vDSO/parse_vdso.c` does.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::sys::Timespec;

pub const AT_SYSINFO_EHDR: usize = 33;

#[cfg(target_arch = "x86_64")]
pub const CLOCK_GETTIME: (&[u8], &[u8]) = (b"__vdso_clock_gettime", b"LINUX_2.6");
#[cfg(target_arch = "aarch64")]
pub const CLOCK_GETTIME: (&[u8], &[u8]) = (b"__kernel_clock_gettime", b"LINUX_2.6.39");

/// `int clock_gettime(clockid_t, struct __kernel_timespec *)`, returning 0
/// or `-errno`.
pub type ClockGettime = unsafe extern "C" fn(i32, *mut Timespec) -> i32;

/// The vDSO's `clock_gettime`, or 0.
static CLOCK_GETTIME_FN: AtomicUsize = AtomicUsize::new(0);

/// Resolve the vDSO's functions. Called once at startup, before any thread
/// exists; until then (and without a vDSO) the syscalls are used.
pub fn init() {
    let Some(base) = crate::start::auxv(AT_SYSINFO_EHDR).filter(|&b| b != 0) else { return };
    let Some(img) = (unsafe { image(base) }) else { return };
    if let Some(off) = lookup(img, CLOCK_GETTIME.0, CLOCK_GETTIME.1) {
        CLOCK_GETTIME_FN.store(base + off, Ordering::Relaxed);
    }
}

/// The vDSO's `clock_gettime`, if [`init`] found one.
#[inline]
pub fn clock_gettime() -> Option<ClockGettime> {
    match CLOCK_GETTIME_FN.load(Ordering::Relaxed) {
        0 => None,
        f => Some(unsafe { core::mem::transmute::<usize, ClockGettime>(f) }),
    }
}

/// The vDSO image mapped at `base`, as far as its `PT_LOAD` segment reaches.
///
/// # Safety
/// `base` must be the kernel's `AT_SYSINFO_EHDR`: a mapped, page-aligned
/// ELF image of at least one page that is never unmapped.
pub unsafe fn image(base: usize) -> Option<&'static [u8]> {
    // the headers and program headers sit in the first page
    let head = unsafe { core::slice::from_raw_parts(base as *const u8, MIN_PAGE) };
    let len = image_size(head)?.max(MIN_PAGE);
    Some(unsafe { core::slice::from_raw_parts(base as *const u8, len) })
}

const MIN_PAGE: usize = 4096;

// ---- ELF64 ----
const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const DYN_SIZE: usize = 16;
const SYM_SIZE: usize = 24;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: u64 = 0;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_GNU_HASH: u64 = 0x6fff_fef5;
const DT_VERSYM: u64 = 0x6fff_fff0;
const DT_VERDEF: u64 = 0x6fff_fffc;
const STT_FUNC: u8 = 2;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const SHN_UNDEF: u16 = 0;
const VER_FLG_BASE: u16 = 1;

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off.checked_add(2)?)?.try_into().ok()?))
}
fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off.checked_add(4)?)?.try_into().ok()?))
}
fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off.checked_add(8)?)?.try_into().ok()?))
}
/// `base + i * size`, overflow-checked.
fn index(base: usize, i: usize, size: usize) -> Option<usize> {
    base.checked_add(i.checked_mul(size)?)
}

struct Phdr {
    ty: u32,
    offset: usize,
    vaddr: usize,
    filesz: usize,
}

/// The program headers, after checking the ELF header: a little-endian
/// ELF64 (the machine is not checked: the kernel maps a vDSO for this one).
fn phdrs(img: &[u8]) -> Option<impl Iterator<Item = Phdr> + '_> {
    if img.get(..6)? != b"\x7fELF\x02\x01" {
        return None;
    }
    let phoff = usize::try_from(u64_at(img, 32)?).ok()?;
    let phentsize = u16_at(img, 54)? as usize;
    let phnum = u16_at(img, 56)? as usize;
    if phentsize != PHDR_SIZE {
        return None;
    }
    Some((0..phnum).map_while(move |i| {
        let p = index(phoff, i, PHDR_SIZE).filter(|&p| p < img.len())?;
        Some(Phdr {
            ty: u32_at(img, p)?,
            offset: usize::try_from(u64_at(img, p + 8)?).ok()?,
            vaddr: usize::try_from(u64_at(img, p + 16)?).ok()?,
            filesz: usize::try_from(u64_at(img, p + 32)?).ok()?,
        })
    }))
}

/// How many bytes of the image the loaded segment covers (the end of the
/// first `PT_LOAD`'s file contents), given at least its headers.
pub fn image_size(head: &[u8]) -> Option<usize> {
    let load = phdrs(head)?.find(|p| p.ty == PT_LOAD)?;
    load.offset.checked_add(load.filesz).filter(|&n| n >= EHDR_SIZE)
}

/// Find the function `name` with symbol version `version` (any version if
/// the image has no version tables), returning its offset into `img`.
pub fn lookup(img: &[u8], name: &[u8], version: &[u8]) -> Option<usize> {
    let t = Tables::parse(img)?;
    let mut found = None;
    let mut visit = |i| {
        found = t.matches(i, name, version);
        found.is_none()
    };
    match (t.gnu_hash, t.hash) {
        (Some(h), _) => t.gnu_hash_chain(h, gnu_hash_of(name), &mut visit)?,
        (None, Some(h)) => t.hash_chain(h, elf_hash_of(name), &mut visit)?,
        (None, None) => return None,
    }
    found
}

/// The dynamic tables, as offsets into the image (all below its length).
struct Tables<'a> {
    img: &'a [u8],
    /// a virtual address minus its offset in the image
    bias: usize,
    strtab: usize,
    symtab: usize,
    hash: Option<usize>,
    gnu_hash: Option<usize>,
    /// `DT_VERSYM`, `DT_VERDEF`
    versym: Option<(usize, usize)>,
}

impl<'a> Tables<'a> {
    /// Follow the first `PT_LOAD` and the `PT_DYNAMIC` program headers to the
    /// tables.
    fn parse(img: &'a [u8]) -> Option<Tables<'a>> {
        let mut load = None;
        let mut dynamic = None;
        for p in phdrs(img)? {
            match p.ty {
                PT_LOAD if load.is_none() => load = Some(p),
                PT_DYNAMIC => dynamic = Some(p),
                _ => {}
            }
        }
        let (load, dynamic) = (load?, dynamic?);
        let bias = load.vaddr.checked_sub(load.offset)?;
        let mut t = Tables { img, bias, strtab: 0, symtab: 0, hash: None, gnu_hash: None, versym: None };

        let (mut strtab, mut symtab, mut hash, mut gnu_hash, mut versym, mut verdef) = (None, None, None, None, None, None);
        let end = dynamic.offset.checked_add(dynamic.filesz)?;
        let mut d = dynamic.offset;
        while d.checked_add(DYN_SIZE)? <= end {
            let (tag, val) = (u64_at(img, d)?, u64_at(img, d + 8)?);
            d += DYN_SIZE;
            let slot = match tag {
                DT_NULL => break,
                DT_STRTAB => &mut strtab,
                DT_SYMTAB => &mut symtab,
                DT_HASH => &mut hash,
                DT_GNU_HASH => &mut gnu_hash,
                DT_VERSYM => &mut versym,
                DT_VERDEF => &mut verdef,
                _ => continue,
            };
            *slot = Some(t.at(val)?);
        }
        (t.strtab, t.symtab, t.hash, t.gnu_hash, t.versym) = (strtab?, symtab?, hash, gnu_hash, versym.zip(verdef));
        Some(t)
    }

    /// A virtual address in the loaded segment, as an offset into the image.
    fn at(&self, vaddr: u64) -> Option<usize> {
        usize::try_from(vaddr).ok()?.checked_sub(self.bias).filter(|&o| o < self.img.len())
    }

    /// Whether symbol `i` is the defined function `name@version`, and if so
    /// its offset.
    fn matches(&self, i: usize, name: &[u8], version: &[u8]) -> Option<usize> {
        let s = index(self.symtab, i, SYM_SIZE).filter(|&s| s < self.img.len())?;
        let st_name = u32_at(self.img, s)? as usize;
        let info = *self.img.get(s + 4)?;
        let shndx = u16_at(self.img, s + 6)?;
        let value = u64_at(self.img, s + 8)?;
        if info & 0xf != STT_FUNC || !matches!(info >> 4, STB_GLOBAL | STB_WEAK) || shndx == SHN_UNDEF {
            return None;
        }
        if !self.str_eq(st_name, name)? {
            return None;
        }
        if let Some((versym, verdef)) = self.versym {
            let ver = u16_at(self.img, index(versym, i, 2)?)? & 0x7fff;
            if !self.has_version(verdef, ver, version)? {
                return None;
            }
        }
        self.at(value)
    }

    /// Whether version index `ver` is named `version` in the `Elf64_Verdef`
    /// list at `verdef`.
    fn has_version(&self, mut verdef: usize, ver: u16, version: &[u8]) -> Option<bool> {
        // (offsets below the image length plus a field offset cannot overflow)
        // each entry is at least 20 bytes, which bounds the walk
        for _ in 0..self.img.len() / 20 {
            let flags = u16_at(self.img, verdef + 2)?;
            let ndx = u16_at(self.img, verdef + 4)?;
            let aux = u32_at(self.img, verdef + 12)? as usize;
            let next = u32_at(self.img, verdef + 16)? as usize;
            if flags & VER_FLG_BASE == 0 && ndx & 0x7fff == ver {
                let vda_name = u32_at(self.img, verdef.checked_add(aux)?)? as usize;
                return self.str_eq(vda_name, version);
            }
            if next == 0 {
                return Some(false);
            }
            verdef = verdef.checked_add(next).filter(|&v| v < self.img.len())?;
        }
        None
    }

    /// Whether the NUL-terminated string at `strtab + off` is `s`.
    fn str_eq(&self, off: usize, s: &[u8]) -> Option<bool> {
        let start = self.strtab.checked_add(off)?;
        let t = self.img.get(start..)?;
        Some(t.len() > s.len() && &t[..s.len()] == s && t[s.len()] == 0)
    }

    /// Call `f` with each symbol index in `hash`'s bucket for `h`, while it
    /// returns true (`DT_HASH`: `nbucket, nchain, bucket[], chain[]`).
    fn hash_chain(&self, hash: usize, h: u32, mut f: impl FnMut(usize) -> bool) -> Option<()> {
        let nbucket = u32_at(self.img, hash)? as usize;
        let nchain = u32_at(self.img, hash + 4)? as usize;
        if nbucket == 0 {
            return None;
        }
        let buckets = hash + 8;
        let chains = index(buckets, nbucket, 4)?;
        let mut i = u32_at(self.img, index(buckets, h as usize % nbucket, 4)?)? as usize;
        // a chain visits each of the nchain symbols at most once, and each
        // has a 4-byte chain entry in the image
        for _ in 0..nchain.min(self.img.len() / 4) {
            if i == 0 || i >= nchain || !f(i) {
                return Some(());
            }
            i = u32_at(self.img, index(chains, i, 4)?)? as usize;
        }
        Some(())
    }

    /// The same for `DT_GNU_HASH`: `nbuckets, symoffset, bloom_size,
    /// bloom_shift, bloom[], buckets[], chain[]`, where a chain is a run of
    /// consecutive symbols whose last hash has bit 0 set.
    fn gnu_hash_chain(&self, hash: usize, h: u32, mut f: impl FnMut(usize) -> bool) -> Option<()> {
        let nbuckets = u32_at(self.img, hash)? as usize;
        let symoffset = u32_at(self.img, hash + 4)? as usize;
        let bloom_size = u32_at(self.img, hash + 8)? as usize;
        if nbuckets == 0 {
            return None;
        }
        let buckets = index(hash + 16, bloom_size, 8)?;
        let chain = index(buckets, nbuckets, 4)?;
        let mut i = u32_at(self.img, index(buckets, h as usize % nbuckets, 4)?)? as usize;
        if i == 0 {
            return Some(());
        }
        // each step reads a new 4-byte chain entry, which bounds the walk
        for _ in 0..self.img.len() / 4 {
            let c = u32_at(self.img, index(chain, i.checked_sub(symoffset)?, 4)?)?;
            if (c | 1) == (h | 1) && !f(i) {
                return Some(());
            }
            if c & 1 != 0 {
                return Some(());
            }
            i = i.checked_add(1)?;
        }
        Some(())
    }
}

/// The SysV ELF hash (`DT_HASH`).
fn elf_hash_of(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &c in name {
        h = (h << 4).wrapping_add(c as u32);
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// The GNU hash (`DT_GNU_HASH`): djb2.
fn gnu_hash_of(name: &[u8]) -> u32 {
    name.iter().fold(5381u32, |h, &c| h.wrapping_mul(33).wrapping_add(c as u32))
}

#[cfg(kani)]
mod proofs {
    use super::*;

    // `lookup` is `Tables::parse`, then a hash chain walk calling
    // `Tables::matches` on each symbol. Each stage is proved on its own, for
    // any bytes and any offsets: one proof over all of it does not finish.
    // The images are small to keep the proofs tractable; every loop is cut
    // off by the image size, so the unwind bounds cover them.

    fn any_img<const N: usize>(buf: &[u8; N]) -> &[u8] {
        &buf[..kani::any_where(|&l: &usize| l <= N)]
    }
    fn any_offset(img: &[u8]) -> usize {
        kani::any_where(|&o: &usize| o < img.len())
    }

    /// The headers and dynamic section of any bytes parse without panicking
    /// or overflowing, to tables inside the image.
    #[kani::proof]
    #[kani::unwind(8)]
    fn parse_any_bytes() {
        let buf: [u8; 112] = kani::any();
        let img = any_img(&buf);
        if let Some(t) = Tables::parse(img) {
            assert!(t.strtab < img.len() && t.symtab < img.len());
            assert!(t.hash.is_none_or(|h| h < img.len()) && t.gnu_hash.is_none_or(|h| h < img.len()));
            assert!(t.versym.is_none_or(|(s, d)| s < img.len() && d < img.len()));
        }
        if let Some(n) = image_size(img) {
            assert!(n >= EHDR_SIZE);
        }
    }

    fn any_tables(img: &[u8]) -> Tables<'_> {
        let versym = if kani::any() { Some((any_offset(img), any_offset(img))) } else { None };
        Tables { img, bias: kani::any(), strtab: any_offset(img), symtab: any_offset(img), hash: None, gnu_hash: None, versym }
    }

    /// Checking any symbol against any tables (its name, version and
    /// address) does not panic, and an address found lies inside the image.
    #[kani::proof]
    #[kani::unwind(4)]
    fn match_any_symbol() {
        let buf: [u8; 64] = kani::any();
        let img = any_img(&buf);
        kani::assume(!img.is_empty());
        let t = any_tables(img);
        if let Some(off) = t.matches(kani::any(), b"f", b"V") {
            assert!(off < img.len());
        }
    }

    /// Walking any `DT_HASH` or `DT_GNU_HASH` chain terminates without
    /// panicking, visiting at most one symbol per 4 bytes of image.
    #[kani::proof]
    #[kani::unwind(14)]
    fn walk_any_hash_chain() {
        let buf: [u8; 48] = kani::any();
        let img = any_img(&buf);
        kani::assume(!img.is_empty());
        let t = any_tables(img);
        let mut visited = 0;
        let stop: usize = kani::any();
        let mut visit = |_| {
            visited += 1;
            visited != stop
        };
        if kani::any() {
            let _ = t.hash_chain(any_offset(img), kani::any(), &mut visit);
        } else {
            let _ = t.gnu_hash_chain(any_offset(img), kani::any(), &mut visit);
        }
        assert!(visited <= img.len() / 4);
    }

    /// The hash functions match their reference values.
    #[kani::proof]
    fn hashes() {
        assert_eq!(gnu_hash_of(b""), 5381);
        assert_eq!(gnu_hash_of(b"printf"), 0x156b_2bb8);
        assert_eq!(elf_hash_of(b"printf"), 0x0779_05a6);
    }
}
