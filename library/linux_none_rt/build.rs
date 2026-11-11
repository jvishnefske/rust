// `linux_none`: the target is *-unknown-linux-none, where this crate is the
// whole C runtime (it defines `_start`). Elsewhere (the host, for unit tests
// and Kani) it builds without the entry point.
fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os == "linux" && env.is_empty() {
        println!("cargo:rustc-cfg=linux_none");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
