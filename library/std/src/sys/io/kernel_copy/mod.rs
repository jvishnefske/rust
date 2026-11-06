cfg_select! {
    linux_none => {
        // upstream's Linux implementation, over a libc-shaped shim
        mod linux;
        mod linux_none;
    }
    any(target_os = "linux", target_os = "android") => {
        mod linux;
    }
    _ => {}
}
