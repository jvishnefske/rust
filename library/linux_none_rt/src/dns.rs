//! A DNS stub resolver, as `getaddrinfo` needs one: the configuration in
//! `/etc/resolv.conf`, A and AAAA queries over UDP (and TCP when an answer
//! is truncated), and CNAME chains inside an answer.
//!
//! It follows glibc's semantics where they differ from musl's: each
//! nameserver is asked in turn, `timeout` is per server and attempt, and a
//! name with at least `ndots` dots is tried as-is before the `search`
//! domains. Replies count only if they come from the server asked and
//! carry the query's (random) id and question.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::sys;

/// Nameservers kept from the configuration, as in glibc and musl.
pub const MAXNS: usize = 3;
/// Bytes of `search` domains kept.
const MAXSEARCH: usize = 256;
/// A name in wire format, with its final empty label. (Kani proves the code
/// with shorter names: nothing depends on the value.)
const MAXNAME: usize = if cfg!(kani) { 12 } else { 255 };
/// CNAMEs followed inside one answer.
const MAXCNAME: usize = 8;
/// Compression pointers followed inside one name.
const MAXJUMPS: usize = 32;
/// The largest query: header, name, type and class.
const MAXQUERY: usize = 12 + MAXNAME + 4;

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

const RCODE_NOERROR: u8 = 0;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;

/// Why a lookup failed; each corresponds to an `EAI_*` code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The name does not exist, has no addresses or is not a valid domain
    /// name (`EAI_NONAME`).
    NoName,
    /// No server answered in time, or each failed temporarily
    /// (`EAI_AGAIN`).
    Again,
    /// A server refused the query or answered with something unusable
    /// (`EAI_FAIL`).
    Fail,
    /// A system call failed with this errno (`EAI_SYSTEM`).
    Sys(i32),
}

/// Which address families to look up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Any,
    V4,
    V6,
}

/// The resolver configuration: what `/etc/resolv.conf` says.
#[derive(Clone, Debug)]
pub struct Config {
    pub nameservers: [Option<SocketAddr>; MAXNS],
    /// How long to wait for one server, per attempt.
    pub timeout_ms: u32,
    /// How many times to go through the servers.
    pub attempts: u32,
    /// Names with at least this many dots are tried as-is first.
    pub ndots: u32,
    /// Space-separated search domains.
    search: [u8; MAXSEARCH],
    search_len: usize,
}

impl Config {
    /// No servers or search domains, and the default options
    /// (`timeout:5 attempts:2 ndots:1`).
    pub fn new() -> Config {
        Config { nameservers: [None; MAXNS], timeout_ms: 5000, attempts: 2, ndots: 1, search: [0; MAXSEARCH], search_len: 0 }
    }

    /// Parses a `resolv.conf`: `nameserver`, `search`, `domain` and the
    /// `options` `timeout:`, `attempts:` and `ndots:` (capped as glibc
    /// does). Without a `nameserver` line, the server is `127.0.0.1`.
    pub fn parse(text: &[u8]) -> Config {
        let mut conf = Config::new();
        for line in text.split(|&b| b == b'\n') {
            let line = line.split(|&b| b == b'#' || b == b';').next().unwrap_or(&[]);
            let mut words = line.split(|b| b.is_ascii_whitespace()).filter(|w| !w.is_empty());
            match words.next() {
                Some(b"nameserver") => {
                    if let Some(addr) = words.next().and_then(parse_nameserver) {
                        conf.add_nameserver(addr);
                    }
                }
                // the last `search` or `domain` line wins
                Some(b"search") | Some(b"domain") => {
                    conf.search_len = 0;
                    for w in words {
                        conf.add_search(w);
                    }
                }
                Some(b"options") => {
                    for w in words {
                        let num = |prefix: &[u8], max: u32| w.strip_prefix(prefix).and_then(parse_u32).map(|v| v.min(max));
                        if let Some(v) = num(b"ndots:", 15) {
                            conf.ndots = v;
                        } else if let Some(v) = num(b"timeout:", 30) {
                            conf.timeout_ms = v.max(1) * 1000;
                        } else if let Some(v) = num(b"attempts:", 5) {
                            conf.attempts = v.max(1);
                        }
                    }
                }
                _ => {}
            }
        }
        if conf.nameservers[0].is_none() {
            conf.add_nameserver(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53));
        }
        conf
    }

    /// Adds a server, unless there are [`MAXNS`] already.
    pub fn add_nameserver(&mut self, addr: SocketAddr) -> bool {
        match self.nameservers.iter_mut().find(|s| s.is_none()) {
            Some(slot) => {
                *slot = Some(addr);
                true
            }
            None => false,
        }
    }

    /// Adds a search domain (a trailing dot is dropped), unless the list is
    /// full.
    pub fn add_search(&mut self, domain: &[u8]) -> bool {
        let domain = domain.strip_suffix(b".").unwrap_or(domain);
        let start = self.search_len + (self.search_len > 0) as usize;
        if domain.is_empty() || start + domain.len() > MAXSEARCH {
            return false;
        }
        if self.search_len > 0 {
            self.search[self.search_len] = b' ';
        }
        self.search[start..start + domain.len()].copy_from_slice(domain);
        self.search_len = start + domain.len();
        true
    }

    /// The search domains, in order.
    pub fn search(&self) -> impl Iterator<Item = &[u8]> {
        self.search[..self.search_len].split(|&b| b == b' ').filter(|d| !d.is_empty())
    }
}

/// `1.2.3.4` or `fe80::1%2` (a numeric scope; interface names need
/// `if_nametoindex`, which is not here).
fn parse_nameserver(word: &[u8]) -> Option<SocketAddr> {
    let mut parts = word.splitn(2, |&b| b == b'%');
    let ip: IpAddr = core::str::from_utf8(parts.next()?).ok()?.parse().ok()?;
    Some(match ip {
        IpAddr::V4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, 53)),
        IpAddr::V6(ip) => {
            let scope = parts.next().and_then(parse_u32).unwrap_or(0);
            SocketAddr::V6(SocketAddrV6::new(ip, 53, 0, scope))
        }
    })
}

fn parse_u32(s: &[u8]) -> Option<u32> {
    if s.is_empty() || s.len() > 9 || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(s.iter().fold(0, |n, &d| n * 10 + (d - b'0') as u32))
}

/// A domain name in wire format: length-prefixed labels, ending with the
/// empty label.
#[derive(Clone, Copy)]
pub struct Name {
    buf: [u8; MAXNAME],
    len: usize,
}

impl Name {
    /// `www.example.com` (or with a trailing dot) in wire format. Labels
    /// must be 1 to 63 bytes, the whole name at most 255 in wire format.
    pub fn from_text(text: &[u8]) -> Option<Name> {
        let text = text.strip_suffix(b".").unwrap_or(text);
        let mut name = Name { buf: [0; MAXNAME], len: 0 };
        if text.is_empty() || text.len() + 2 > MAXNAME {
            return None;
        }
        for label in text.split(|&b| b == b'.') {
            if label.is_empty() || label.len() > 63 {
                return None;
            }
            name.buf[name.len] = label.len() as u8;
            name.buf[name.len + 1..name.len + 1 + label.len()].copy_from_slice(label);
            name.len += 1 + label.len();
        }
        name.len += 1;
        Some(name)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Domain names compare without regard to ASCII case. (Lengths are at most
/// 63, so they are never letters.)
impl PartialEq for Name {
    fn eq(&self, other: &Name) -> bool {
        self.as_bytes().eq_ignore_ascii_case(other.as_bytes())
    }
}

impl Eq for Name {}

impl core::fmt::Debug for Name {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.as_bytes().escape_ascii())
    }
}

/// Reads the (possibly compressed) name at `pos` in `msg`. Returns it and
/// the position after it, or None if it is malformed, too long or points
/// outside the message.
pub fn read_name(msg: &[u8], mut pos: usize) -> Option<(Name, usize)> {
    let mut name = Name { buf: [0; MAXNAME], len: 0 };
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos)? as usize;
        match len & 0xc0 {
            0 if len == 0 => {
                if name.len + 1 > MAXNAME {
                    return None;
                }
                name.buf[name.len] = 0;
                name.len += 1;
                return Some((name, end.unwrap_or(pos + 1)));
            }
            0 => {
                let label = msg.get(pos + 1..pos + 1 + len)?;
                // room for this label and the final empty one
                if name.len + 1 + len + 1 > MAXNAME {
                    return None;
                }
                name.buf[name.len] = len as u8;
                name.buf[name.len + 1..name.len + 1 + len].copy_from_slice(label);
                name.len += 1 + len;
                pos += 1 + len;
            }
            0xc0 => {
                jumps += 1;
                if jumps > MAXJUMPS {
                    return None;
                }
                let target = (len & 0x3f) << 8 | *msg.get(pos + 1)? as usize;
                end.get_or_insert(pos + 2);
                pos = target;
            }
            // 0x40 and 0x80 are extended and reserved label types
            _ => return None,
        }
    }
}

/// A query for `name`'s records of `qtype`, with recursion desired.
/// Returns its length in `out`.
pub fn build_query(out: &mut [u8; MAXQUERY], id: u16, name: &Name, qtype: u16) -> usize {
    out[..12].copy_from_slice(&[0, 0, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    out[..2].copy_from_slice(&id.to_be_bytes());
    let n = name.as_bytes();
    out[12..12 + n.len()].copy_from_slice(n);
    out[12 + n.len()..16 + n.len()].copy_from_slice(&[(qtype >> 8) as u8, qtype as u8, 0, CLASS_IN as u8]);
    16 + n.len()
}

fn be16(msg: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]))
}

/// What a reply's header says, once it is known to answer our question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub rcode: u8,
    pub truncated: bool,
}

/// Whether `msg` is a reply to the query `id` for `qname`/`qtype`: the
/// response bit and standard opcode, the id, and the question echoed
/// back.
pub fn check_reply(msg: &[u8], id: u16, qname: &Name, qtype: u16) -> Option<Reply> {
    let flags = be16(msg, 2)?;
    if be16(msg, 0)? != id || flags & 0x8000 == 0 || flags & 0x7800 != 0 || be16(msg, 4)? != 1 {
        return None;
    }
    let (name, pos) = read_name(msg, 12)?;
    if name != *qname || be16(msg, pos)? != qtype || be16(msg, pos + 2)? != CLASS_IN {
        return None;
    }
    Some(Reply { rcode: (flags & 0xf) as u8, truncated: flags & 0x0200 != 0 })
}

/// One resource record of a message's answer section.
struct Record {
    owner: Name,
    rtype: u16,
    class: u16,
    /// rdata's offset and length in the message
    data: usize,
    len: usize,
}

/// The answer section of a reply that passed [`check_reply`].
struct Answers<'a> {
    msg: &'a [u8],
    pos: usize,
    left: u16,
}

impl<'a> Answers<'a> {
    fn new(msg: &'a [u8]) -> Option<Answers<'a>> {
        let (_, pos) = read_name(msg, 12)?;
        Some(Answers { msg, pos: pos + 4, left: be16(msg, 6)? })
    }
}

impl Iterator for Answers<'_> {
    type Item = Option<Record>;

    /// The next record, `Some(None)` if it is malformed (which ends the
    /// iteration).
    fn next(&mut self) -> Option<Option<Record>> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let rec = (|| {
            let (owner, pos) = read_name(self.msg, self.pos)?;
            let (rtype, class, len) = (be16(self.msg, pos)?, be16(self.msg, pos + 2)?, be16(self.msg, pos + 8)? as usize);
            let data = pos + 10;
            if data + len > self.msg.len() {
                return None;
            }
            self.pos = data + len;
            Some(Record { owner, rtype, class, data, len })
        })();
        if rec.is_none() {
            self.left = 0;
        }
        Some(rec)
    }
}

/// Appends the addresses of type `qtype` that `msg` (which passed
/// [`check_reply`]) gives `qname`, following CNAMEs from `qname`, to
/// `out[*n..]`, skipping duplicates and stopping when `out` is full.
/// Returns None if the answer section is malformed.
pub fn parse_answers(msg: &[u8], qname: &Name, qtype: u16, out: &mut [IpAddr], n: &mut usize) -> Option<()> {
    // where the chain of CNAMEs leads (the records may come in any order)
    let mut target = *qname;
    'hops: for _ in 0..MAXCNAME {
        for rec in Answers::new(msg)? {
            let rec = rec?;
            if rec.rtype == TYPE_CNAME && rec.class == CLASS_IN && rec.owner == target {
                let (alias, end) = read_name(msg, rec.data)?;
                if end != rec.data + rec.len {
                    return None;
                }
                if alias != target {
                    target = alias;
                    continue 'hops;
                }
            }
        }
        break;
    }
    for rec in Answers::new(msg)? {
        let rec = rec?;
        if rec.rtype != qtype || rec.class != CLASS_IN || rec.owner != target {
            continue;
        }
        let data = &msg[rec.data..rec.data + rec.len];
        let ip = match (qtype, data.len()) {
            (TYPE_A, 4) => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(data).unwrap())),
            (TYPE_AAAA, 16) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).unwrap())),
            _ => return None,
        };
        if *n < out.len() && !out[..*n].contains(&ip) {
            out[*n] = ip;
            *n += 1;
        }
    }
    Some(())
}

/// Looks `name` up as [`Config`] says, trying the search domains, and
/// writes its addresses to `out` (IPv4 before IPv6) and returns how many.
/// `random` makes the query ids. `buf` receives replies: 512 bytes are
/// enough for UDP, TCP replies need up to 65535.
pub fn lookup(conf: &Config, name: &[u8], family: Family, random: &mut dyn FnMut() -> u16, buf: &mut [u8], out: &mut [IpAddr]) -> Result<usize, Error> {
    let absolute = name.ends_with(b".");
    let full = Name::from_text(name).ok_or(Error::NoName)?;
    let dots = name.iter().filter(|&&b| b == b'.').count() as u32;
    let mut query = |qname: &Name| query(conf, qname, family, random, buf, out);
    if absolute || conf.search().next().is_none() {
        return query(&full);
    }
    if dots >= conf.ndots {
        match query(&full) {
            Err(Error::NoName) => {}
            r => return r,
        }
    }
    for domain in conf.search() {
        let mut text = [0u8; MAXNAME];
        if name.len() + 1 + domain.len() > text.len() {
            continue;
        }
        text[..name.len()].copy_from_slice(name);
        text[name.len()] = b'.';
        text[name.len() + 1..name.len() + 1 + domain.len()].copy_from_slice(domain);
        let Some(qname) = Name::from_text(&text[..name.len() + 1 + domain.len()]) else { continue };
        match query(&qname) {
            Err(Error::NoName) => {}
            r => return r,
        }
    }
    if dots < conf.ndots { query(&full) } else { Err(Error::NoName) }
}

/// Asks the servers in turn for `qname`'s addresses.
fn query(conf: &Config, qname: &Name, family: Family, random: &mut dyn FnMut() -> u16, buf: &mut [u8], out: &mut [IpAddr]) -> Result<usize, Error> {
    let qtypes: &[u16] = match family {
        Family::Any => &[TYPE_A, TYPE_AAAA],
        Family::V4 => &[TYPE_A],
        Family::V6 => &[TYPE_AAAA],
    };
    let mut err = Error::Again;
    for _ in 0..conf.attempts.max(1) {
        for ns in conf.nameservers.iter().flatten() {
            match ask(ns, qname, qtypes, conf.timeout_ms, random, buf, out) {
                Ok(0) => return Err(Error::NoName),
                Ok(n) => {
                    // IPv4 first: the order connecting tries them in
                    v4_first(&mut out[..n]);
                    return Ok(n);
                }
                // an authoritative answer: no point asking elsewhere
                Err(Error::NoName) => return Err(Error::NoName),
                Err(e @ Error::Sys(_)) => return Err(e),
                Err(e) => err = e,
            }
        }
    }
    Err(err)
}

/// Moves the IPv4 addresses ahead of the IPv6 ones, keeping their order
/// otherwise (an insertion sort: there are few).
fn v4_first(addrs: &mut [IpAddr]) {
    for i in 1..addrs.len() {
        let mut j = i;
        while j > 0 && addrs[j - 1].is_ipv6() && addrs[j].is_ipv4() {
            addrs.swap(j - 1, j);
            j -= 1;
        }
    }
}

/// A file descriptor, closed on drop.
struct Fd(i32);

impl Drop for Fd {
    fn drop(&mut self) {
        let _ = sys::close(self.0);
    }
}

fn now_ms() -> u64 {
    let t = sys::clock_gettime(sys::CLOCK_MONOTONIC);
    t.sec as u64 * 1000 + t.nsec as u64 / 1_000_000
}

/// Waits until `fd` has one of `events` or `deadline` passes; false on
/// timeout.
fn wait(fd: &Fd, events: i16, deadline: u64) -> Result<bool, Error> {
    loop {
        let now = now_ms();
        if now >= deadline {
            return Ok(false);
        }
        let left = deadline - now;
        let ts = sys::Timespec { sec: (left / 1000) as i64, nsec: (left % 1000) as i64 * 1_000_000 };
        let mut pfd = sys::PollFd { fd: fd.0, events, revents: 0 };
        match unsafe { sys::ppoll(&mut pfd, 1, &ts) } {
            Ok(0) | Err(sys::EINTR) => {}
            Ok(_) => return Ok(true),
            Err(e) => return Err(Error::Sys(e)),
        }
    }
}

/// `addr` as a `sockaddr_in` or `sockaddr_in6`.
fn sockaddr(addr: &SocketAddr) -> ([u8; 28], u32) {
    let mut sa = [0u8; 28];
    sa[2..4].copy_from_slice(&addr.port().to_be_bytes());
    match addr {
        SocketAddr::V4(a) => {
            sa[..2].copy_from_slice(&sys::AF_INET.to_ne_bytes());
            sa[4..8].copy_from_slice(&a.ip().octets());
            (sa, 16)
        }
        SocketAddr::V6(a) => {
            sa[..2].copy_from_slice(&sys::AF_INET6.to_ne_bytes());
            sa[8..24].copy_from_slice(&a.ip().octets());
            sa[24..28].copy_from_slice(&a.scope_id().to_ne_bytes());
            (sa, 28)
        }
    }
}

/// Whether the `sockaddr` `recvfrom` filled in is `addr` (family, port and
/// address).
fn same_addr(sa: &[u8; 28], len: u32, addr: &SocketAddr) -> bool {
    let (want, want_len) = sockaddr(addr);
    // family and port, then the address (not sin6_flowinfo or the scope)
    let ip = if addr.is_ipv4() { 4..8 } else { 8..24 };
    len == want_len && sa[..4] == want[..4] && sa[ip.clone()] == want[ip]
}

/// One query in flight.
struct Pending {
    qtype: u16,
    id: u16,
    query: [u8; MAXQUERY],
    len: usize,
    done: bool,
}

/// Asks `ns` for each of `qtypes` at once over UDP, waiting at most
/// `timeout_ms`, and collects the addresses into `out`. A truncated reply is
/// asked again over TCP.
fn ask(ns: &SocketAddr, qname: &Name, qtypes: &[u16], timeout_ms: u32, random: &mut dyn FnMut() -> u16, buf: &mut [u8], out: &mut [IpAddr]) -> Result<usize, Error> {
    let domain = if ns.is_ipv4() { sys::AF_INET } else { sys::AF_INET6 };
    let fd = Fd(sys::socket(domain, sys::SOCK_DGRAM | sys::SOCK_CLOEXEC | sys::SOCK_NONBLOCK, 0).map_err(Error::Sys)?);
    let (sa, salen) = sockaddr(ns);
    // connected, so that an ICMP error ends the wait early; the kernel then
    // also drops datagrams from elsewhere, which we check again anyway
    if unsafe { sys::connect(fd.0, sa.as_ptr(), salen) }.is_err() {
        return Err(Error::Again);
    }
    let mut pending = [const { Pending { qtype: 0, id: 0, query: [0; MAXQUERY], len: 0, done: true } }; 2];
    for (i, &qtype) in qtypes.iter().enumerate() {
        let mut id = random();
        if i > 0 && id == pending[0].id {
            id ^= 1;
        }
        let p = &mut pending[i];
        *p = Pending { qtype, id, query: [0; MAXQUERY], len: 0, done: false };
        p.len = build_query(&mut p.query, id, qname, qtype);
        if unsafe { sys::sendto(fd.0, p.query.as_ptr(), p.len, sys::MSG_NOSIGNAL, core::ptr::null(), 0) }.is_err() {
            return Err(Error::Again);
        }
    }
    let deadline = now_ms() + timeout_ms as u64;
    let mut n = 0;
    let mut servfail = false;
    while pending.iter().any(|p| !p.done) {
        if !wait(&fd, sys::POLLIN, deadline)? {
            // keep what one family gave if the other went unanswered
            return if n > 0 { Ok(n) } else { Err(Error::Again) };
        }
        let mut from = [0u8; 28];
        let mut fromlen = from.len() as u32;
        let len = match unsafe { sys::recvfrom(fd.0, buf.as_mut_ptr(), buf.len(), 0, from.as_mut_ptr(), &mut fromlen) } {
            Ok(len) => len,
            Err(sys::EAGAIN | sys::EINTR) => continue,
            Err(_) => return Err(Error::Again),
        };
        if !same_addr(&from, fromlen, ns) {
            continue;
        }
        let Some(p) = pending.iter_mut().find(|p| !p.done && be16(&buf[..len], 0) == Some(p.id)) else { continue };
        let Some(mut reply) = check_reply(&buf[..len], p.id, qname, p.qtype) else { continue };
        let mut len = len;
        if reply.truncated {
            len = ask_tcp(ns, &p.query[..p.len], deadline, buf)?;
            reply = check_reply(&buf[..len], p.id, qname, p.qtype).ok_or(Error::Fail)?;
        }
        p.done = true;
        match reply.rcode {
            RCODE_NOERROR => parse_answers(&buf[..len], qname, p.qtype, out, &mut n).ok_or(Error::Fail)?,
            RCODE_NXDOMAIN => return Err(Error::NoName),
            // as with a timeout, what the other family gave still counts
            RCODE_SERVFAIL => servfail = true,
            _ => return Err(Error::Fail),
        }
    }
    if n == 0 && servfail { Err(Error::Again) } else { Ok(n) }
}

/// Sends `query` to `ns` over TCP and reads the reply into `buf`, by
/// `deadline`. Returns the reply's length.
fn ask_tcp(ns: &SocketAddr, query: &[u8], deadline: u64, buf: &mut [u8]) -> Result<usize, Error> {
    let domain = if ns.is_ipv4() { sys::AF_INET } else { sys::AF_INET6 };
    let fd = Fd(sys::socket(domain, sys::SOCK_STREAM | sys::SOCK_CLOEXEC | sys::SOCK_NONBLOCK, 0).map_err(Error::Sys)?);
    let (sa, salen) = sockaddr(ns);
    match unsafe { sys::connect(fd.0, sa.as_ptr(), salen) } {
        Ok(_) => {}
        Err(sys::EINPROGRESS) => {
            if !wait(&fd, sys::POLLOUT, deadline)? {
                return Err(Error::Again);
            }
            let mut err = 0i32;
            let mut len = 4u32;
            let r = unsafe { sys::getsockopt(fd.0, sys::SOL_SOCKET, sys::SO_ERROR, (&raw mut err).cast(), &mut len) };
            if r.is_err() || err != 0 {
                return Err(Error::Again);
            }
        }
        Err(_) => return Err(Error::Again),
    }
    let mut msg = [0u8; 2 + MAXQUERY];
    msg[..2].copy_from_slice(&(query.len() as u16).to_be_bytes());
    msg[2..2 + query.len()].copy_from_slice(query);
    let mut sent = 0;
    while sent < 2 + query.len() {
        match unsafe { sys::sendto(fd.0, msg[sent..].as_ptr(), 2 + query.len() - sent, sys::MSG_NOSIGNAL, core::ptr::null(), 0) } {
            Ok(k) => sent += k,
            Err(sys::EAGAIN | sys::EINTR) => {
                if !wait(&fd, sys::POLLOUT, deadline)? {
                    return Err(Error::Again);
                }
            }
            Err(_) => return Err(Error::Again),
        }
    }
    let mut len = [0u8; 2];
    read_exact(&fd, &mut len, deadline)?;
    let len = u16::from_be_bytes(len) as usize;
    let dst = buf.get_mut(..len).ok_or(Error::Fail)?;
    read_exact(&fd, dst, deadline)?;
    Ok(len)
}

fn read_exact(fd: &Fd, mut dst: &mut [u8], deadline: u64) -> Result<(), Error> {
    while !dst.is_empty() {
        match unsafe { sys::read(fd.0, dst.as_mut_ptr(), dst.len()) } {
            Ok(0) => return Err(Error::Fail),
            Ok(k) => dst = &mut dst[k..],
            Err(sys::EAGAIN | sys::EINTR) => {
                if !wait(fd, sys::POLLIN, deadline)? {
                    return Err(Error::Again);
                }
            }
            Err(_) => return Err(Error::Again),
        }
    }
    Ok(())
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Any message decodes without panicking (or looping: compression
    /// pointers may point anywhere), and a name read is well-formed wire
    /// format with its end inside the message.
    #[kani::proof]
    // Bounded to keep the proof tractable: 8 bytes hold pointer loops and
    // short labels; the loop runs at most MAXJUMPS + 8 times.
    #[kani::unwind(42)]
    fn read_name_any_message() {
        let buf: [u8; 8] = kani::any();
        let len: usize = kani::any_where(|&l| l <= 8);
        let pos: usize = kani::any();
        if let Some((name, end)) = read_name(&buf[..len], pos) {
            let b = name.as_bytes();
            assert!(!b.is_empty() && b.len() <= MAXNAME && b[b.len() - 1] == 0);
            assert!(end > pos && end <= len);
        }
    }

    /// Encoding a name and decoding it again gives the same name.
    #[kani::proof]
    #[kani::unwind(14)]
    fn name_round_trip() {
        let text: [u8; 6] = kani::any();
        let len: usize = kani::any_where(|&l| l <= 6);
        if let Some(name) = Name::from_text(&text[..len]) {
            let (back, end) = read_name(name.as_bytes(), 0).unwrap();
            assert!(back == name && end == name.as_bytes().len());
        }
    }
}
