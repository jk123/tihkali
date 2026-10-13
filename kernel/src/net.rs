//! smoltcp glue: boot-time link/ARP/ICMP smoke (N1) + persistent interface
//! and socket pool with syscall-driven servicing (N2).
//!
//! Time: everything here uses the raw `cntpct` counter — the boot smoke
//! runs at EL1 while DAIF still masks IRQs (TICKS never advance before
//! EL0), and cntpct is valid in every context.
//!
//! Servicing model: no NIC IRQs. `poll_tick()` is called from the
//! sync-exception tail (trap.rs) and the idle loop (main.rs); a poll that
//! changes socket state wakes all sleepers (the coarse `wake_sleeping`
//! used by pipes), so a process blocked in recv/connect re-runs its
//! syscall on the next schedule (≤10 ms via the timer tick).

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};

use smoltcp::iface::{Config, Interface, PollResult, SocketSet, SocketStorage};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::icmp::{
    Endpoint as IcmpEndpoint, PacketBuffer as IcmpBuffer, PacketMetadata as IcmpMeta,
    Socket as IcmpSocket,
};
use smoltcp::socket::tcp;
use smoltcp::socket::udp;
use smoltcp::storage::RingBuffer;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address,
};

use tihkali_hal::kprintln;

use crate::virtio_net;

const IP: [u8; 4] = [10, 0, 2, 15];
const GW: [u8; 4] = [10, 0, 2, 2];
const IDENT: u16 = 0x1234;
const DEADLINE_MS: i64 = 1500; // boot smoke; must fit before the sessions'
                               // first scripted input at 3 s

/// Socket pool (Linux fd → pool slot via FdTarget::Socket).
const NSOCK: usize = 8;
const TCP_BUF: usize = 4096;
const UDP_META: usize = 4;
const UDP_PAY: usize = 1024;
/// Connection establishment timeout handed to smoltcp (guards a blackholed
/// SYN so a blocked connect() eventually fails instead of hanging).
const CONNECT_TIMEOUT_MS: u64 = 8_000;
/// Ephemeral local port base for connect() (smoltcp rejects local port 0).
const EPHEMERAL_PORT: u16 = 49_500;

/// Kernel errnos (NetBSD numbering; the Linux epilogue translates).
pub const EAGAIN_L: u8 = 35;
pub const EINVAL: u8 = 22;
pub const EBADF: u8 = 9;
pub const EAFNOSUPPORT: u8 = 47;
pub const ENOTCONN: u8 = 57;
pub const ECONNREFUSED: u8 = 61;
const ECONNRESET: u8 = 54;
const EISCONN: u8 = 56;
const EIO: u8 = 5;
const ENOBUFS: u8 = 55;

/// Gateway MAC sniffed off the wire: bit 63 = seen, bits 0..47 = address.
static ARP_GW: AtomicU64 = AtomicU64::new(0);

/// `UnsafeCell` wrapper (the file.rs/fs.rs pattern) — single-core, so no
/// locking; edition 2024 forbids direct `&mut STATIC` references.
struct NetCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for NetCell<T> {}

static IFACE: NetCell<Option<Interface>> = NetCell(UnsafeCell::new(None));
static SOCK_STORE: NetCell<[SocketStorage<'static>; NSOCK]> =
    NetCell(UnsafeCell::new([SocketStorage::EMPTY; NSOCK]));

#[derive(Clone, Copy, PartialEq)]
pub enum SockKind {
    Tcp,
    Udp,
}
struct SockMeta {
    used: bool,
    kind: SockKind,
    /// Set handle for this slot (handle == pool index by construction:
    /// both pick the first free position, and open/remove keep them in
    /// lockstep) — stored so later syscalls can re-acquire it.
    handle: Option<smoltcp::iface::SocketHandle>,
    /// TCP: connect() initiated / waiting for establishment.
    connecting: bool,
    /// TCP: link established at least once (distinguishes EISCONN/refused).
    connected: bool,
    /// UDP/TCP: local port chosen by bind() (0 = ephemeral at connect).
    lport: u16,
}
const SOCK_META_EMPTY: SockMeta = SockMeta {
    used: false,
    kind: SockKind::Tcp,
    handle: None,
    connecting: false,
    connected: false,
    lport: 0,
};
static SOCK_META: NetCell<[SockMeta; NSOCK]> =
    NetCell(UnsafeCell::new([SOCK_META_EMPTY; NSOCK]));

static TCP_RX: NetCell<[u8; NSOCK * TCP_BUF]> = NetCell(UnsafeCell::new([0; NSOCK * TCP_BUF]));
static TCP_TX: NetCell<[u8; NSOCK * TCP_BUF]> = NetCell(UnsafeCell::new([0; NSOCK * TCP_BUF]));
static UDP_RX_META: NetCell<[udp::PacketMetadata; NSOCK * UDP_META]> =
    NetCell(UnsafeCell::new([udp::PacketMetadata::EMPTY; NSOCK * UDP_META]));
static UDP_RX_PAY: NetCell<[u8; NSOCK * UDP_PAY]> = NetCell(UnsafeCell::new([0; NSOCK * UDP_PAY]));
static UDP_TX_META: NetCell<[udp::PacketMetadata; NSOCK * UDP_META]> =
    NetCell(UnsafeCell::new([udp::PacketMetadata::EMPTY; NSOCK * UDP_META]));
static UDP_TX_PAY: NetCell<[u8; NSOCK * UDP_PAY]> = NetCell(UnsafeCell::new([0; NSOCK * UDP_PAY]));

fn iface_mut() -> Option<&'static mut Interface> {
    unsafe { (*IFACE.0.get()).as_mut() }
}

fn sock_store() -> &'static mut [SocketStorage<'static>; NSOCK] {
    unsafe { &mut *SOCK_STORE.0.get() }
}

fn meta() -> &'static mut [SockMeta; NSOCK] {
    unsafe { &mut *SOCK_META.0.get() }
}

fn tcp_buf(i: usize, tx: bool) -> &'static mut [u8] {
    let base = if tx {
        TCP_TX.0.get() as *mut u8
    } else {
        TCP_RX.0.get() as *mut u8
    };
    unsafe { core::slice::from_raw_parts_mut(base.add(i * TCP_BUF), TCP_BUF) }
}

fn udp_bufs(i: usize, tx: bool) -> (&'static mut [udp::PacketMetadata], &'static mut [u8]) {
    let (meta_base, pay_base) = if tx {
        (
            UDP_TX_META.0.get() as *mut udp::PacketMetadata,
            UDP_TX_PAY.0.get() as *mut u8,
        )
    } else {
        (
            UDP_RX_META.0.get() as *mut udp::PacketMetadata,
            UDP_RX_PAY.0.get() as *mut u8,
        )
    };
    unsafe {
        (
            core::slice::from_raw_parts_mut(meta_base.add(i * UDP_META), UDP_META),
            core::slice::from_raw_parts_mut(pay_base.add(i * UDP_PAY), UDP_PAY),
        )
    }
}

/// Milliseconds from the raw `cntpct` counter (IRQ-state independent —
/// see the module docs).
fn now_ms() -> i64 {
    let (ticks, freq): (u64, u64);
    unsafe {
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) ticks, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack));
    }
    let freq = if freq == 0 { 62_500_000 } else { freq };
    ((ticks / freq) as i64) * 1000 + (((ticks % freq) * 1000) / freq) as i64
}

// ---------- device (phy) ----------

/// Device wrapper over the polled virtio-net driver (stateless).
struct NetDev;

struct NetRx<'a> {
    id: usize,
    len: usize,
    _m: PhantomData<&'a ()>,
}

struct NetTx<'a> {
    _m: PhantomData<&'a ()>,
}

impl<'a> RxToken for NetRx<'a> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let bytes = virtio_net::rx_bytes(self.id, self.len);
        // Sniff an ARP reply from the gateway for the resolution print
        // (smoltcp 0.12 exposes no public neighbor-cache accessor).
        if bytes.len() >= 42
            && bytes[12] == 0x08
            && bytes[13] == 0x06 // ethertype ARP
            && bytes[20] == 0x00
            && bytes[21] == 0x02 // opcode reply
            && bytes[28] == GW[0]
            && bytes[29] == GW[1]
            && bytes[30] == GW[2]
            && bytes[31] == GW[3]
            && ARP_GW.load(Ordering::Acquire) >> 63 == 0
        {
            let mac = u64::from_be_bytes([
                0,
                bytes[22],
                bytes[23],
                bytes[24],
                bytes[25],
                bytes[26],
                bytes[27],
                0,
            ]);
            ARP_GW.store(mac | (1 << 63), Ordering::Release);
            kprintln!(
                "net: arp 10.0.2.2 -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                bytes[22],
                bytes[23],
                bytes[24],
                bytes[25],
                bytes[26],
                bytes[27]
            );
        }
        let r = f(bytes);
        virtio_net::repost_rx(self.id);
        r
    }
}

impl<'a> TxToken for NetTx<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        virtio_net::transmit_with(len, f)
    }
}

impl Device for NetDev {
    type RxToken<'a> = NetRx<'a> where Self: 'a;
    type TxToken<'a> = NetTx<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let (id, len) = virtio_net::poll_rx()?;
        Some((
            NetRx { id, len, _m: PhantomData },
            NetTx { _m: PhantomData },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(NetTx { _m: PhantomData })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1514;
        caps.max_burst_size = Some(1);
        caps.medium = Medium::Ethernet;
        caps
    }
}

// ---------- boot smoke (N1) ----------

/// Bring up driver + interface (static). Called by `smoke()` at boot;
/// later users only need `poll_tick`/socket ops, which no-op until this
/// has succeeded once.
fn init_iface() -> Result<(), &'static str> {
    if iface_mut().is_some() {
        return Ok(());
    }
    virtio_net::init()?;
    let mac = virtio_net::mac();
    let mut dev = NetDev;
    let mut cfg = Config::new(HardwareAddress::Ethernet(EthernetAddress::from_bytes(&mac)));
    cfg.random_seed = 0x7469_6b61;
    let mut iface = Interface::new(cfg, &mut dev, Instant::from_millis(now_ms()));
    iface.update_ip_addrs(|v| {
        let _ = v.push(IpCidr::new(
            IpAddress::Ipv4(Ipv4Address::new(IP[0], IP[1], IP[2], IP[3])),
            24,
        ));
    });
    if iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(GW[0], GW[1], GW[2], GW[3]))
        .is_err()
    {
        return Err("route table full");
    }
    unsafe { *IFACE.0.get() = Some(iface) };
    kprintln!(
        "net: link up, {}.{}.{}.{}/24, mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        IP[0],
        IP[1],
        IP[2],
        IP[3],
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );
    Ok(())
}

/// Boot-time link/ARP/ICMP smoke test. Prints on success:
/// `net: link up, ...` / `net: arp 10.0.2.2 -> ...` / `net: icmp reply ...`
/// Never panics: failures become `net:` error lines.
pub fn smoke() {
    if let Err(e) = init_iface() {
        kprintln!("net: no nic ({e})");
        return;
    }
    let iface = iface_mut().expect("iface set by init_iface");
    let mut dev = NetDev;

    // ICMP socket lives in a *local* set for the duration of the smoke
    // test — the persistent pool is only for user sockets (N2).
    let mut rx_meta = [IcmpMeta::EMPTY; 2];
    let mut rx_pay = [0u8; 64];
    let mut tx_meta = [IcmpMeta::EMPTY; 2];
    let mut tx_pay = [0u8; 64];
    let icmp_sock = IcmpSocket::new(
        IcmpBuffer::new(&mut rx_meta[..], &mut rx_pay[..]),
        IcmpBuffer::new(&mut tx_meta[..], &mut tx_pay[..]),
    );
    let mut sock_store = [SocketStorage::EMPTY; 1];
    let mut sockets = SocketSet::new(&mut sock_store[..]);
    let handle = sockets.add(icmp_sock);

    let mut req = [0u8; 12]; // 8-byte ICMP header + 4-byte payload
    req[0] = 8; // echo request
    req[1] = 0; // code
    req[4] = (IDENT >> 8) as u8;
    req[5] = (IDENT & 0xff) as u8;
    req[6] = 0; // seq
    req[7] = 1;
    req[8..].copy_from_slice(b"ping");
    let mut sum = 0u32;
    for pair in req.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let cksum = !(sum as u16);
    req[2] = (cksum >> 8) as u8;
    req[3] = (cksum & 0xff) as u8;

    {
        let sock = sockets.get_mut::<IcmpSocket>(handle);
        if let Err(e) = sock.bind(IcmpEndpoint::Ident(IDENT)) {
            kprintln!("net: icmp bind failed ({e:?})");
            return;
        }
        if let Err(e) = sock.send_slice(
            &req,
            IpAddress::Ipv4(Ipv4Address::new(GW[0], GW[1], GW[2], GW[3])),
        ) {
            kprintln!("net: icmp queue failed ({e:?})");
            return;
        }
    }

    let start_ms = now_ms();
    let deadline = start_ms + DEADLINE_MS;
    let mut rbuf = [0u8; 64];
    loop {
        let _ = iface.poll(
            Instant::from_millis(now_ms()),
            &mut dev,
            &mut sockets,
        );

        let mut got: Option<usize> = None;
        {
            let sock = sockets.get_mut::<IcmpSocket>(handle);
            if let Ok((data, _from)) = sock.recv() {
                let n = data.len().min(rbuf.len());
                rbuf[..n].copy_from_slice(&data[..n]);
                got = Some(n);
            }
        }
        if let Some(n) = got {
            if n >= 8 && rbuf[0] == 0 {
                let rtt = (now_ms() - start_ms).max(0);
                kprintln!(
                    "net: icmp reply from 10.0.2.2, {} bytes, rtt ~{} ms",
                    n - 8,
                    rtt
                );
                return;
            }
        }

        if now_ms() >= deadline {
            kprintln!("net: icmp timeout (no reply from 10.0.2.2)");
            return;
        }
        core::hint::spin_loop();
    }
}

// ---------- ongoing servicing (N2) ----------

/// One servicing pass: drain RX, flush TX, run smoltcp timers; wake all
/// sleepers when socket state changed (they re-check and re-sleep).
/// Called from the sync-exception tail and the idle loop. No-ops until
/// `init_iface()` has run (boot exceptions before smoke).
pub fn poll_tick() {
    let Some(iface) = iface_mut() else { return };
    let mut dev = NetDev;
    let store = sock_store();
    let mut set = SocketSet::new(&mut store[..]);
    match iface.poll(
        Instant::from_millis(now_ms()),
        &mut dev,
        &mut set,
    ) {
        PollResult::None => {}
        PollResult::SocketStateChanged => crate::proc::wake_sleeping(),
    }
}

/// Run `f` against a SocketSet view of the persistent pool.
fn with_set<R>(f: impl FnOnce(&mut SocketSet<'static>) -> R) -> R {
    let store = sock_store();
    let mut set = SocketSet::new(&mut store[..]);
    f(&mut set)
}

// ---------- socket pool ops (called from syscall arms) ----------

/// socket(AF_INET, type) → pool slot. `kind`: 1=SOCK_STREAM, 2=SOCK_DGRAM
/// (Linux and BSD share these values; higher bits are flags).
pub fn sock_open(kind: u32) -> Result<usize, u8> {
    if iface_mut().is_none() {
        return Err(EIO);
    }
    let k = match kind {
        1 => SockKind::Tcp,
        2 => SockKind::Udp,
        _ => return Err(EINVAL),
    };
    let meta = meta();
    let Some(slot) = meta.iter().position(|m| !m.used) else {
        return Err(ENOBUFS);
    };
    let handle = with_set(|set| match k {
        SockKind::Tcp => {
            let rx = tcp_buf(slot, false);
            let tx = tcp_buf(slot, true);
            let mut s = tcp::Socket::new(RingBuffer::new(rx), RingBuffer::new(tx));
            s.set_timeout(Some(Duration::from_millis(CONNECT_TIMEOUT_MS)));
            set.add(s)
        }
        SockKind::Udp => {
            let (rm, rp) = udp_bufs(slot, false);
            let (tm, tp) = udp_bufs(slot, true);
            let s = udp::Socket::new(
                udp::PacketBuffer::new(rm, rp),
                udp::PacketBuffer::new(tm, tp),
            );
            set.add(s)
        }
    });
    meta[slot].handle = Some(handle);
    meta[slot].used = true;
    meta[slot].kind = k;
    meta[slot].connecting = false;
    meta[slot].connected = false;
    meta[slot].lport = 0;
    Ok(slot)
}

/// Close a pool slot (close(2)/process exit). NOTE (N2): fd tables are
/// copy-on-fork without refcounts, so a socket fd shared across fork
/// would be freed by whichever process exits first — the N2 userland
/// never does that; revisit with fd refcounts when jobs+sockets mix.
pub fn sock_close(slot: usize) {
    let meta = meta();
    if slot >= NSOCK || !meta[slot].used {
        return;
    }
    let handle = meta[slot].handle.expect("used slot has a handle");
    with_set(|set| {
        set.remove(handle);
    });
    meta[slot] = SOCK_META_EMPTY;
}

fn tcp_sock<'a>(set: &'a mut SocketSet<'static>, slot: usize) -> &'a mut tcp::Socket<'static> {
    let h = meta()[slot].handle.expect("used slot has a handle");
    set.get_mut::<tcp::Socket>(h)
}

fn udp_sock<'a>(set: &'a mut SocketSet<'static>, slot: usize) -> &'a mut udp::Socket<'static> {
    let h = meta()[slot].handle.expect("used slot has a handle");
    set.get_mut::<udp::Socket>(h)
}

/// bind(2): UDP binds for real; TCP records the local port for connect.
pub fn sock_bind(slot: usize, ip: [u8; 4], port: u16) -> Result<(), u8> {
    let meta = meta();
    if slot >= NSOCK || !meta[slot].used {
        return Err(EBADF);
    }
    match meta[slot].kind {
        SockKind::Tcp => {
            meta[slot].lport = port;
            Ok(())
        }
        SockKind::Udp => with_set(|set| {
            let s = udp_sock(set, slot);
            if s.is_open() {
                return Err(EINVAL);
            }
            s.bind((
                IpAddress::Ipv4(Ipv4Address::new(ip[0], ip[1], ip[2], ip[3])),
                port,
            ))
            .map_err(|_| EINVAL)
        }),
    }
}

pub enum Conn {
    Done,
    Progress,
    Failed,
}

/// connect(2) state machine — idempotent so the syscall can re-run after
/// each wake (ELR rewind) until ESTABLISHED / failure.
pub fn sock_connect(slot: usize, ip: [u8; 4], port: u16) -> Result<Conn, u8> {
    let meta = meta();
    if slot >= NSOCK || !meta[slot].used || meta[slot].kind != SockKind::Tcp {
        return Err(EBADF);
    }
    if port == 0 {
        return Err(EINVAL);
    }
    if meta[slot].connected {
        return Err(EISCONN);
    }
    with_set(|set| {
        if !meta[slot].connecting {
            let remote = IpEndpoint::new(
                IpAddress::Ipv4(Ipv4Address::new(ip[0], ip[1], ip[2], ip[3])),
                port,
            );
            let local = if meta[slot].lport != 0 {
                meta[slot].lport
            } else {
                EPHEMERAL_PORT + slot as u16
            };
            let iface = iface_mut().expect("iface");
            let cx = iface.context();
            let s = tcp_sock(set, slot);
            match s.connect(cx, remote, local) {
                Ok(()) => meta[slot].connecting = true,
                Err(tcp::ConnectError::Unaddressable) => return Err(EINVAL),
                Err(tcp::ConnectError::InvalidState) => {
                    // Re-entry in an odd state: fall through to state check.
                }
            }
        }
        let st = tcp_sock(set, slot).state();
        use tcp::State;
        match st {
            State::Established => {
                meta[slot].connecting = false;
                meta[slot].connected = true;
                Ok(Conn::Done)
            }
            State::Closed if meta[slot].connecting => {
                // smoltcp aborted (RST refused, or the connect timeout).
                meta[slot].connecting = false;
                Ok(Conn::Failed)
            }
            _ => Ok(Conn::Progress),
        }
    })
}

/// send(2)/sendto(2) on a TCP socket: queues bytes (partial counts as
/// success; a full buffer → EAGAIN for the caller to surface).
pub fn sock_send(slot: usize, data: &[u8]) -> Result<usize, u8> {
    let meta = meta();
    if slot >= NSOCK || !meta[slot].used {
        return Err(EBADF);
    }
    match meta[slot].kind {
        SockKind::Udp => Err(EINVAL), // UDP needs sendto's destination
        SockKind::Tcp => with_set(|set| {
            let s = tcp_sock(set, slot);
            match s.send_slice(data) {
                Ok(0) if !data.is_empty() => Err(EAGAIN_L),
                Ok(n) => Ok(n),
                Err(tcp::SendError::InvalidState) => {
                    Err(if meta[slot].connected {
                        ECONNRESET
                    } else {
                        ENOTCONN
                    })
                }
            }
        }),
    }
}

/// sendto(2) on a UDP socket (auto-binds an ephemeral local port first).
pub fn sock_send_to(slot: usize, data: &[u8], ip: [u8; 4], port: u16) -> Result<usize, u8> {
    let meta = meta();
    if slot >= NSOCK || !meta[slot].used {
        return Err(EBADF);
    }
    if meta[slot].kind != SockKind::Udp {
        return Err(EINVAL);
    }
    with_set(|set| {
        let s = udp_sock(set, slot);
        if !s.is_open() {
            let p = if meta[slot].lport != 0 {
                meta[slot].lport
            } else {
                40_000 + slot as u16
            };
            if s.bind((
                IpAddress::Ipv4(Ipv4Address::UNSPECIFIED),
                p,
            ))
            .is_err()
            {
                return Err(EINVAL);
            }
        }
        let ep = IpEndpoint::new(
            IpAddress::Ipv4(Ipv4Address::new(ip[0], ip[1], ip[2], ip[3])),
            port,
        );
        match s.send_slice(data, ep) {
            Ok(()) => Ok(data.len()),
            Err(udp::SendError::BufferFull) => Err(EAGAIN_L),
            Err(udp::SendError::Unaddressable) => Err(EINVAL),
        }
    })
}

/// recv(2)/recvfrom(2): copies into the caller's user buffer (already
/// range-checked). Returns 0 = TCP EOF. EAGAIN = caller should sleep.
/// UDP: if `from` is provided it receives (ip, port) of the sender.
pub fn sock_recv(
    slot: usize,
    buf: &mut [u8],
    from: Option<&mut ([u8; 4], u16)>,
) -> Result<usize, u8> {
    let meta = meta();
    if slot >= NSOCK || !meta[slot].used {
        return Err(EBADF);
    }
    match meta[slot].kind {
        SockKind::Tcp => with_set(|set| {
            let s = tcp_sock(set, slot);
            match s.recv_slice(buf) {
                // Ok(0) = buffer empty (connection alive) → would-block.
                // Err(Finished) = FIN seen AND buffer drained → real EOF.
                Ok(0) => Err(EAGAIN_L),
                Ok(n) => Ok(n),
                Err(tcp::RecvError::Finished) => Ok(0),
                Err(tcp::RecvError::InvalidState) => Err(if meta[slot].connected {
                    ECONNRESET
                } else {
                    ENOTCONN
                }),
            }
        }),
        SockKind::Udp => with_set(|set| {
            let s = udp_sock(set, slot);
            match s.recv_slice(buf) {
                Ok((n, meta_ep)) => {
                    if let Some(from) = from {
                        let IpAddress::Ipv4(a) = meta_ep.endpoint.addr;
                        from.0.copy_from_slice(&a.octets());
                        from.1 = meta_ep.endpoint.port;
                    }
                    Ok(n)
                }
                Err(_) => Err(EAGAIN_L), // empty → caller sleeps
            }
        }),
    }
}

/// poll(2) readiness for a socket fd: (POLLIN-ish, POLLOUT-ish).
pub fn sock_poll(slot: usize) -> Option<(bool, bool)> {
    let meta = meta();
    if slot >= NSOCK || !meta[slot].used {
        return None;
    }
    with_set(|set| match meta[slot].kind {
        SockKind::Tcp => {
            let s = tcp_sock(set, slot);
            let recv = s.can_recv() || !s.may_recv(); // data, or EOF readable
            let send = s.can_send();
            Some((recv, send))
        }
        SockKind::Udp => {
            let s = udp_sock(set, slot);
            Some((s.can_recv(), s.can_send()))
        }
    })
}
