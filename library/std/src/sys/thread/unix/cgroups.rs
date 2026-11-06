//! Currently not covered
//! * cgroup v2 in non-standard mountpoints
//! * paths containing control characters or spaces, since those would be escaped in procfs
//!   output and we don't unescape

use crate::borrow::Cow;
use crate::ffi::OsString;
use crate::fs::{File, exists};
use crate::io::{BufRead, Read};
use crate::os::unix::ffi::OsStringExt;
use crate::path::{Path, PathBuf};
use crate::str::from_utf8;

#[derive(PartialEq)]
enum Cgroup {
    V1,
    V2,
}

/// Returns cgroup CPU quota in core-equivalents, rounded down or usize::MAX if the quota cannot
/// be determined or is not set.
pub(super) fn quota() -> usize {
    let mut quota = usize::MAX;
    if cfg!(miri) {
        // Attempting to open a file fails under default flags due to isolation.
        // And Miri does not have parallelism anyway.
        return quota;
    }

    let _: Option<()> = try {
        let mut buf = Vec::with_capacity(128);
        // find our place in the cgroup hierarchy
        File::open("/proc/self/cgroup").ok()?.read_to_end(&mut buf).ok()?;
        let (cgroup_path, version) =
            buf.split(|&c| c == b'\n').fold(None, |previous, line| {
                let mut fields = line.splitn(3, |&c| c == b':');
                // 2nd field is a list of controllers for v1 or empty for v2
                let version = match fields.nth(1) {
                    Some(b"") => Cgroup::V2,
                    Some(controllers)
                        if from_utf8(controllers)
                            .is_ok_and(|c| c.split(',').any(|c| c == "cpu")) =>
                    {
                        Cgroup::V1
                    }
                    _ => return previous,
                };

                // already-found v1 trumps v2 since it explicitly specifies its controllers
                if previous.is_some() && version == Cgroup::V2 {
                    return previous;
                }

                let path = fields.last()?;
                // skip leading slash
                Some((path[1..].to_owned(), version))
            })?;
        let cgroup_path = PathBuf::from(OsString::from_vec(cgroup_path));

        quota = match version {
            Cgroup::V1 => quota_v1(cgroup_path),
            Cgroup::V2 => quota_v2(cgroup_path),
        };
    };

    quota
}

fn quota_v2(group_path: PathBuf) -> usize {
    let mut quota = usize::MAX;

    let mut path = PathBuf::with_capacity(128);
    let mut read_buf = String::with_capacity(20);

    // standard mount location defined in file-hierarchy(7) manpage
    let cgroup_mount = "/sys/fs/cgroup";

    path.push(cgroup_mount);
    path.push(&group_path);

    path.push("cgroup.controllers");

    // skip if we're not looking at cgroup2
    if matches!(exists(&path), Err(_) | Ok(false)) {
        return usize::MAX;
    };

    path.pop();

    let _: Option<()> = try {
        while path.starts_with(cgroup_mount) {
            path.push("cpu.max");

            read_buf.clear();

            if File::open(&path).and_then(|mut f| f.read_to_string(&mut read_buf)).is_ok() {
                let raw_quota = read_buf.lines().next()?;
                let mut raw_quota = raw_quota.split(' ');
                let limit = raw_quota.next()?;
                let period = raw_quota.next()?;
                match (limit.parse::<usize>(), period.parse::<usize>()) {
                    (Ok(limit), Ok(period)) if period > 0 => {
                        quota = quota.min(limit / period);
                    }
                    _ => {}
                }
            }

            path.pop(); // pop filename
            path.pop(); // pop dir
        }
    };

    quota
}

fn quota_v1(group_path: PathBuf) -> usize {
    let mut quota = usize::MAX;
    let mut path = PathBuf::with_capacity(128);
    let mut read_buf = String::with_capacity(20);

    // Hardcode commonly used locations mentioned in the cgroups(7) manpage
    // if that doesn't work scan mountinfo and adjust `group_path` for bind-mounts
    let mounts: &[fn(&Path) -> Option<(_, &Path)>] = &[
        |p| Some((Cow::Borrowed("/sys/fs/cgroup/cpu"), p)),
        |p| Some((Cow::Borrowed("/sys/fs/cgroup/cpu,cpuacct"), p)),
        // this can be expensive on systems with tons of mountpoints
        // but we only get to this point when /proc/self/cgroups explicitly indicated
        // this process belongs to a cpu-controller cgroup v1 and the defaults didn't work
        find_mountpoint,
    ];

    for mount in mounts {
        let Some((mount, group_path)) = mount(&group_path) else { continue };

        path.clear();
        path.push(mount.as_ref());
        path.push(&group_path);

        // skip if we guessed the mount incorrectly
        if matches!(exists(&path), Err(_) | Ok(false)) {
            continue;
        }

        while path.starts_with(mount.as_ref()) {
            let mut parse_file = |name| {
                path.push(name);
                read_buf.clear();

                let f = File::open(&path);
                path.pop(); // restore buffer before any early returns
                f.ok()?.read_to_string(&mut read_buf).ok()?;
                let parsed = read_buf.trim().parse::<usize>().ok()?;

                Some(parsed)
            };

            let limit = parse_file("cpu.cfs_quota_us");
            let period = parse_file("cpu.cfs_period_us");

            match (limit, period) {
                (Some(limit), Some(period)) if period > 0 => quota = quota.min(limit / period),
                _ => {}
            }

            path.pop();
        }

        // we passed the try_exists above so we should have traversed the correct hierarchy
        // when reaching this line
        break;
    }

    quota
}

/// Scan mountinfo for cgroup v1 mountpoint with a cpu controller
///
/// If the cgroupfs is a bind mount then `group_path` is adjusted to skip
/// over the already-included prefix
fn find_mountpoint(group_path: &Path) -> Option<(Cow<'static, str>, &Path)> {
    let mut reader = File::open_buffered("/proc/self/mountinfo").ok()?;
    let mut line = String::with_capacity(256);
    loop {
        line.clear();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }

        let line = line.trim();
        let mut items = line.split(' ');

        let sub_path = items.nth(3)?;
        let mount_point = items.next()?;
        let mount_opts = items.next_back()?;
        let filesystem_type = items.nth_back(1)?;

        if filesystem_type != "cgroup" || !mount_opts.split(',').any(|opt| opt == "cpu") {
            // not a cgroup / not a cpu-controller
            continue;
        }

        let sub_path = Path::new(sub_path).strip_prefix("/").ok()?;

        if !group_path.starts_with(sub_path) {
            // this is a bind-mount and the bound subdirectory
            // does not contain the cgroup this process belongs to
            continue;
        }

        let trimmed_group_path = group_path.strip_prefix(sub_path).ok()?;

        return Some((Cow::Owned(mount_point.to_owned()), trimmed_group_path));
    }

    None
}
