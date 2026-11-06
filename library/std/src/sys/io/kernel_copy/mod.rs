cfg_select! {
    // io::copy copies through a userspace buffer (no copy_file_range,
    // sendfile or splice yet)
    linux_none => {}
    any(target_os = "linux", target_os = "android") => {
        mod linux;
    }
    _ => {}
}
