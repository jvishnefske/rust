//! The running executable's ELF program headers, from the auxiliary vector:
//! what `dl_iterate_phdr` reports for a static executable. The unwinder finds
//! the `.eh_frame_hdr` section through them (`PT_GNU_EH_FRAME`), and the
//! backtrace symbolizer the loaded segments.

pub const PT_LOAD: u32 = 1;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;

/// `Elf64_Phdr`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/// The executable's program headers (`AT_PHDR`, `AT_PHNUM`), or none before
/// [`crate::start::init`].
pub fn program_headers() -> &'static [Phdr] {
    use crate::start::{AT_PHDR, AT_PHNUM, auxv};
    match (auxv(AT_PHDR), auxv(AT_PHNUM)) {
        // SAFETY: the kernel maps the headers for the life of the process
        (Some(p), Some(n)) if p != 0 => unsafe { core::slice::from_raw_parts(p as *const Phdr, n) },
        _ => &[],
    }
}

/// What the headers' addresses must be offset by to get run-time addresses
/// (`dlpi_addr`): zero for a non-PIE executable. `at_phdr` is where the
/// headers themselves were found.
pub fn load_bias(phdrs: &[Phdr], at_phdr: usize) -> usize {
    match phdrs.iter().find(|h| h.p_type == PT_PHDR) {
        Some(h) => at_phdr.wrapping_sub(h.p_vaddr as usize),
        None => 0,
    }
}

/// The run-time address of `.eh_frame_hdr`, from `PT_GNU_EH_FRAME`.
pub fn find_eh_frame_hdr(phdrs: &[Phdr], bias: usize) -> Option<usize> {
    let h = phdrs.iter().find(|h| h.p_type == PT_GNU_EH_FRAME)?;
    Some(bias.wrapping_add(h.p_vaddr as usize))
}

/// [`load_bias`] for the running executable.
pub fn executable_bias() -> usize {
    let phdrs = program_headers();
    load_bias(phdrs, phdrs.as_ptr() as usize)
}

/// [`find_eh_frame_hdr`] for the running executable.
pub fn eh_frame_hdr() -> Option<usize> {
    find_eh_frame_hdr(program_headers(), executable_bias())
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_phdr() -> Phdr {
        Phdr { p_type: kani::any(), p_vaddr: kani::any(), ..Default::default() }
    }

    /// The bias maps `PT_PHDR`'s stated address to where the headers are, and
    /// the `.eh_frame_hdr` address is the first `PT_GNU_EH_FRAME`'s, moved
    /// by the bias.
    #[kani::proof]
    #[kani::unwind(4)]
    fn eh_frame_hdr_is_relocated() {
        let phdrs = [any_phdr(), any_phdr(), any_phdr()];
        let at_phdr: usize = kani::any();
        let bias = load_bias(&phdrs, at_phdr);
        match phdrs.iter().position(|h| h.p_type == PT_PHDR) {
            Some(i) => assert!(bias.wrapping_add(phdrs[i].p_vaddr as usize) == at_phdr),
            None => assert!(bias == 0),
        }
        let found = find_eh_frame_hdr(&phdrs, bias);
        match phdrs.iter().position(|h| h.p_type == PT_GNU_EH_FRAME) {
            Some(i) => {
                assert!(found == Some(bias.wrapping_add(phdrs[i].p_vaddr as usize)));
                assert!(phdrs[..i].iter().all(|h| h.p_type != PT_GNU_EH_FRAME));
            }
            None => assert!(found.is_none()),
        }
    }
}
