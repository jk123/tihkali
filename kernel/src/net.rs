//! smoltcp glue + boot-time ARP/ICMP smoke test (N1).
//!
//! N1 policy: run everything synchronously at boot, exactly like the polled
//! virtio-blk path — no IRQs, no idle/syscall hooks. `smoke()` brings the
//! link up with a static SLIRP config (10.0.2.15/24, gateway 10.0.2.2),
//! resolves the gateway by ARP, sends one ICMP echo request, and prints
//! the results. It never panics: failures become `net:` error lines.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};

use smoltcp::iface::{Config, Interface, SocketSet, SocketStorage};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::icmp::{
    PacketBuffer as IcmpBuffer, PacketMetadata as IcmpMeta, Socket as IcmpSocket,
};
use smoltcp::socket::icmp::Endpoint as IcmpEndpoint;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};

use tihkali_hal::kprintln;

use crate::virtio_net;

const IP: [u8; 4] = [10, 0, 2, 15];
const GW: [u8; 4] = [10, 0, 2, 2];
const IDENT: u16 = 0x1234;
const DEADLINE_MS: i64 = 1500; // must fit before the sessions' first
                               // scripted input at 3 s

/// Gateway MAC sniffed off the wire: bit 63 = seen, bits 0..47 = address.
static ARP_GW: AtomicU64 = AtomicU64::new(0);

/// Milliseconds from the raw `cntpct` counter. The boot-time smoke test
/// runs at EL1 while DAIF still masks IRQs (they are only cleared at EL0
/// entry), so `timer::now()` (TICKS) never advances here — cntpct runs
/// regardless of interrupt state.
fn now_ms() -> i64 {
    let (ticks, freq): (u64, u64);
    unsafe {
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) ticks, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack));
    }
    let freq = if freq == 0 { 62_500_000 } else { freq };
    ((ticks / freq) as i64) * 1000 + (((ticks % freq) * 1000) / freq) as i64
}

/// Device wrapper over the polled virtio-net driver.
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
            let mac = u64::from_be_bytes([0, bytes[22], bytes[23], bytes[24], bytes[25], bytes[26], bytes[27], 0]);
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
        Some((NetRx { id, len, _m: PhantomData }, NetTx { _m: PhantomData }))
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

/// Boot-time link/ARP/ICMP smoke test. Prints on success:
/// `net: link up, ...` / `net: arp 10.0.2.2 -> ...` / `net: icmp reply ...`
pub fn smoke() {
    if let Err(e) = virtio_net::init() {
        kprintln!("net: no nic ({e})");
        return;
    }

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
        kprintln!("net: route table full");
        return;
    }
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

    // ICMP echo socket: full ICMP request in the tx buffer (smoltcp
    // re-emits with a correct checksum on the wire).
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
    // ICMP checksum over the whole message.
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
        if let Err(e) = sock.send_slice(&req, IpAddress::Ipv4(Ipv4Address::new(GW[0], GW[1], GW[2], GW[3])))
        {
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

        // Take one reply, copying it out so the borrow ends immediately.
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
                // echo reply
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
