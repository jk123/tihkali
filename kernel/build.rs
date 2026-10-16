use std::path::Path;
use std::process::Command;

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // Board selects the link address: QEMU virt loads at 0x40080000,
    // the Pi's boot ROM loads kernel8.bin at 0x80000.
    let script = if std::env::var_os("CARGO_FEATURE_RPI3").is_some() {
        "src/arch/link-rpi.ld"
    } else {
        "src/arch/link.ld"
    };
    println!("cargo:rustc-link-arg=-T{dir}/{script}");
    println!("cargo:rerun-if-changed={script}");
    println!("cargo:rerun-if-changed=../user/src/main.rs");
    println!("cargo:rerun-if-changed=../user/src/greet.rs");
    println!("cargo:rerun-if-changed=../user/src/sh.rs");
    println!("cargo:rerun-if-changed=../user/src/nettest.rs");
    println!("cargo:rerun-if-changed=../user/src/netserver.rs");
    println!("cargo:rerun-if-changed=../user/src/netsend.rs");
    println!("cargo:rerun-if-changed=../user/src/sockopt.rs");
    println!("cargo:rerun-if-changed=../user/src/dnsprobe.rs");
    println!("cargo:rerun-if-changed=../user/src/gui.rs");
    println!("cargo:rerun-if-changed=../user/user.ld");
    println!("cargo:rerun-if-changed=assets/motd");
    println!("cargo:rerun-if-changed=assets/demo.sh");
    println!("cargo:rerun-if-changed=assets/resolv.conf");
    println!("cargo:rerun-if-changed=assets/hosts");

    // NetBSD syscall numbers, generated from the upstream master table.
    let out = std::env::var("OUT_DIR").unwrap();
    gen_netbsd_syscall_table(&dir, &out);

    // Build the user programs into a private target dir (nested cargo
    // would deadlock on the parent's target-dir lock, hence OUT_DIR/user).
    let target_dir = std::path::Path::new(&out).join("user-target");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = Command::new(&cargo)
        .args([
            "build",
            "--release",
            "-p",
            "tihkali-user",
            "--target",
            "aarch64-unknown-none",
            "--target-dir",
        ])
        .arg(&target_dir)
        .status()
        .expect("failed to spawn cargo for tihkali-user (is cargo on PATH?)");
    assert!(status.success(), "tihkali-user build failed");

    let bindir = target_dir.join("aarch64-unknown-none/release");
    let sh = bindir.join("tihkali-sh");
    let hello = bindir.join("tihkali-hello");
    let greet = bindir.join("tihkali-greet");
    let nettest = bindir.join("tihkali-nettest");
    let netserver = bindir.join("tihkali-netserver");
    let netsend = bindir.join("tihkali-netsend");
    let sockopt = bindir.join("tihkali-sockopt");
    let dnsprobe = bindir.join("tihkali-dnsprobe");
    let gui = bindir.join("tihkali-gui");
    for p in [&sh, &hello, &greet, &nettest, &netserver, &netsend, &sockopt, &dnsprobe, &gui] {
        assert!(p.exists(), "user binary not produced at {}", p.display());
    }
    // Still used by main.rs until M4 switches pid0/exec to the VFS.
    println!("cargo:rustc-env=TIHKALI_USER_ELF={}", hello.display());
    println!("cargo:rustc-env=TIHKALI_USER_GREET={}", greet.display());
    println!("cargo:rustc-env=TIHKALI_USER_SHELL={}", sh.display());

    // Linux-personality test binary (static musl, linked into the 4 GiB
    // user window; needs tools/fetch-linux-toolchain.sh once).
    let gcc = Path::new(&dir)
        .join("../.toolchain/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc");
    let linux_out = Path::new(&out).join("linux-hello");
    let src = Path::new(&dir).join("assets/c/hello.c");
    let status = Command::new(&gcc)
        .args([
            "-static",
            "-no-pie",
            "-O2",
            "-Wl,-Ttext-segment=0x100000000",
            "-o",
        ])
        .arg(&linux_out)
        .arg(&src)
        .status();
    match status {
        Ok(st) if st.success() => {}
        Ok(_) => panic!("linux hello compile failed (run tools/fetch-linux-toolchain.sh)"),
        Err(e) => panic!("musl gcc not runnable ({e}); run tools/fetch-linux-toolchain.sh"),
    }
    println!("cargo:rerun-if-changed=assets/c/hello.c");

    // Linux syscall depth probe (packed as /bin/linux-probe).
    let probe_out = Path::new(&out).join("linux-probe");
    let probe_src = Path::new(&dir).join("assets/c/probe.c");
    let status = Command::new(&gcc)
        .args(["-static", "-no-pie", "-O2", "-Wl,-Ttext-segment=0x100000000", "-o"])
        .arg(&probe_out)
        .arg(&probe_src)
        .status();
    match status {
        Ok(st) if st.success() => {}
        Ok(_) => panic!("linux probe compile failed"),
        Err(e) => panic!("musl gcc not runnable ({e})"),
    }
    println!("cargo:rerun-if-changed=assets/c/probe.c");

    // N2 TCP probe (packed as /bin/linux-tcp).
    let tcp_out = Path::new(&out).join("linux-tcp");
    let tcp_src = Path::new(&dir).join("assets/c/tcp.c");
    let status = Command::new(&gcc)
        .args(["-static", "-no-pie", "-O2", "-Wl,-Ttext-segment=0x100000000", "-o"])
        .arg(&tcp_out)
        .arg(&tcp_src)
        .status();
    match status {
        Ok(st) if st.success() => {}
        Ok(_) => panic!("linux tcp probe compile failed"),
        Err(e) => panic!("musl gcc not runnable ({e})"),
    }
    println!("cargo:rerun-if-changed=assets/c/tcp.c");

    // Alpine busybox (static ET_EXEC at 0x400000): shift all VAs into the
    // user window. Static aarch64 code addresses everything PC-relatively
    // (adrp/add), so only entry/phdrs and .{init,fini,preinit}_array
    // pointers need adjusting; the binary has no relocations/dynamic section.
    let busybox_src = Path::new(&dir).join("../.toolchain/alpine/busybox");
    let busybox_out = Path::new(&out).join("busybox");
    std::fs::copy(&busybox_src, &busybox_out)
        .unwrap_or_else(|e| panic!("{} (run tools/fetch-alpine-busybox.sh)", e));
    shift_elf_vas(&busybox_out, 0x1_0000_0000 - 0x0040_0000);
    println!("cargo:rerun-if-changed=../.toolchain/alpine/busybox");

    fn shift_elf_vas(path: &std::path::Path, delta: u64) {
        const LO: u64 = 0x3F_0000; // original image was linked at 0x400000,
        const HI: u64 = 0x60_0000; // pointers live in (LO..HI)
        let mut d = std::fs::read(path).expect("read elf");
        let et = u16::from_le_bytes([d[16], d[17]]);
        assert_eq!(et, 2, "busybox must be ET_EXEC (relink with -no-pie)");
        // entry point
        let entry = u64::from_le_bytes(d[0x18..0x20].try_into().unwrap());
        d[0x18..0x20].copy_from_slice(&(entry + delta).to_le_bytes());
        // PT_LOAD p_vaddr/p_paddr
        let phoff = u64::from_le_bytes(d[0x20..0x28].try_into().unwrap()) as usize;
        let phentsz = u16::from_le_bytes([d[0x36], d[0x37]]) as usize;
        let phnum = u16::from_le_bytes([d[0x38], d[0x39]]) as usize;
        for i in 0..phnum {
            let o = phoff + i * phentsz;
            if u32::from_le_bytes(d[o..o + 4].try_into().unwrap()) != 1 {
                continue;
            }
            for fo in [16usize, 24] {
                let o2 = o + fo;
                let v = u64::from_le_bytes(d[o2..o2 + 8].try_into().unwrap());
                d[o2..o2 + 8].copy_from_slice(&(v + delta).to_le_bytes());
            }
        }
        // Absolute pointers baked into sections (no .rela in this binary).
        // Scan .text/.rodata/.data + init/fini/preinit arrays for u64 values
        // inside the original image range and rebase them.
        let shoff = u64::from_le_bytes(d[0x28..0x30].try_into().unwrap()) as usize;
        let shentsz = u16::from_le_bytes([d[0x3a], d[0x3b]]) as usize;
        let shnum = u16::from_le_bytes([d[0x3c], d[0x3d]]) as usize;
        let shstrndx = u16::from_le_bytes([d[0x3e], d[0x3f]]) as usize;
        let str_sh = shoff + shstrndx * shentsz;
        let stroff =
            u64::from_le_bytes(d[str_sh + 0x18..str_sh + 0x20].try_into().unwrap()) as usize;
        let mut patched = 0u32;
        for i in 0..shnum {
            let sh = shoff + i * shentsz;
            let name_off =
                u32::from_le_bytes(d[sh..sh + 4].try_into().unwrap()) as usize + stroff;
            let end = d[name_off..].iter().position(|&b| b == 0).unwrap() + name_off;
            let name = std::str::from_utf8(&d[name_off..end]).unwrap_or("");
            // Only pointer-bearing sections: scanning .text/.rodata also
            // matches unrelated integer constants in the address range.
            if !matches!(
                name,
                ".data.rel.ro" | ".got" | ".data"
                    | ".init_array" | ".fini_array" | ".preinit_array"
            ) {
                continue;
            }
            let off = u64::from_le_bytes(d[sh + 0x18..sh + 0x20].try_into().unwrap()) as usize;
            let sz = u64::from_le_bytes(d[sh + 0x20..sh + 0x28].try_into().unwrap()) as usize;
            let mut k = 0;
            while k + 8 <= sz {
                let v = u64::from_le_bytes(d[off + k..off + k + 8].try_into().unwrap());
                if v > LO && v < HI {
                    d[off + k..off + k + 8].copy_from_slice(&(v + delta).to_le_bytes());
                    patched += 1;
                }
                k += 8;
            }
        }
        if patched == 0 {
            panic!("busybox pointer scan found nothing to patch — layout changed?");
        }
        eprintln!("build.rs: busybox rebased ({patched} pointers +{delta:#x})");
        std::fs::write(path, &d).expect("write elf");
    }

    // Read every payload once (paths resolved above).
    let sh_bytes = std::fs::read(&sh).expect("read tihkali-sh");
    let hello_bytes = std::fs::read(&hello).expect("read tihkali-hello");
    let greet_bytes = std::fs::read(&greet).expect("read tihkali-greet");
    let nettest_bytes = std::fs::read(&nettest).expect("read tihkali-nettest");
    let netserver_bytes = std::fs::read(&netserver).expect("read tihkali-netserver");
    let netsend_bytes = std::fs::read(&netsend).expect("read tihkali-netsend");
    let sockopt_bytes = std::fs::read(&sockopt).expect("read tihkali-sockopt");
    let dnsprobe_bytes = std::fs::read(&dnsprobe).expect("read tihkali-dnsprobe");
    let gui_bytes = std::fs::read(&gui).expect("read tihkali-gui");
    let linux_bytes = std::fs::read(&linux_out).expect("read linux-hello");
    let probe_bytes = std::fs::read(&probe_out).expect("read linux-probe");
    let tcp_bytes = std::fs::read(&tcp_out).expect("read linux-tcp");
    let busybox_bytes = std::fs::read(&busybox_out).expect("read busybox");

    let motd = std::fs::read(Path::new(&dir).join("assets/motd")).expect("read motd");
    let demo_sh = std::fs::read(Path::new(&dir).join("assets/demo.sh")).expect("read demo.sh");
    let resolv_conf =
        std::fs::read(Path::new(&dir).join("assets/resolv.conf")).expect("read resolv.conf");
    let hosts = std::fs::read(Path::new(&dir).join("assets/hosts")).expect("read hosts");

    let mut entries: Vec<CpioEntry> = vec![
        CpioEntry::dir("."),
        CpioEntry::dir("bin"),
        CpioEntry::dir("etc"),
        CpioEntry::file("bin/sh", &sh_bytes),
        CpioEntry::file("bin/hello", &hello_bytes),
        CpioEntry::file("bin/greet", &greet_bytes),
        CpioEntry::file("bin/nettest", &nettest_bytes),
        CpioEntry::file("bin/netserver", &netserver_bytes),
        CpioEntry::file("bin/netsend", &netsend_bytes),
        CpioEntry::file("bin/sockopt", &sockopt_bytes),
        CpioEntry::file("bin/dnsprobe", &dnsprobe_bytes),
        CpioEntry::file("bin/gui", &gui_bytes),
        CpioEntry::file("bin/linux-hello", &linux_bytes),
        CpioEntry::file("bin/linux-probe", &probe_bytes),
        CpioEntry::file("bin/linux-tcp", &tcp_bytes),
        CpioEntry::exe("bin/busybox", &busybox_bytes),
        CpioEntry::file("etc/motd", &motd),
        CpioEntry::file("etc/demo.sh", &demo_sh),
        CpioEntry::file("etc/resolv.conf", &resolv_conf),
        CpioEntry::file("etc/hosts", &hosts),
    ];
    // busybox applet links (Alpine convention: /bin/<applet> -> busybox).
    // ash execs these by name; busybox dispatches on argv[0]'s basename.
    for applet in [
        "cat", "ls", "echo", "head", "tail", "wc", "grep", "sleep", "mkdir", "rm", "rmdir",
        "touch", "cp", "mv", "ln", "pwd", "which", "true", "false", "sort", "seq", "date",
        "uname", "id", "env", "basename", "dirname", "[", "test", "printf", "unzip", "tar",
        "chmod", "stat", "truncate", "readlink", "ping", "wget",
    ] {
        entries.push(CpioEntry::symlink(&format!("bin/{applet}"), "busybox"));
    }
    let image = pack_newc(&entries);

    // Canonical location for the QEMU drive (tools/run.sh reads this path).
    let img_path = Path::new(&dir).join("../target/initramfs.img");
    if let Some(parent) = img_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&img_path, &image).expect("write initramfs.img");
    println!(
        "cargo:rustc-env=TIHKALI_INITRAMFS={}",
        img_path.canonicalize().unwrap_or(img_path).display()
    );
}

struct CpioEntry<'a> {
    name: String,
    mode: u32,
    data: &'a [u8],
}

impl<'a> CpioEntry<'a> {
    fn dir(name: &str) -> Self {
        Self { name: name.into(), mode: 0o040755, data: &[] }
    }
    fn file(name: &str, data: &'a [u8]) -> Self {
        Self { name: name.into(), mode: 0o100644, data }
    }
    fn exe(name: &str, data: &'a [u8]) -> Self {
        Self { name: name.into(), mode: 0o100755, data }
    }
    fn symlink(name: &str, target: &'a str) -> Self {
        Self { name: name.into(), mode: 0o120777, data: target.as_bytes() }
    }
}

/// cpio "newc": 110-byte header, ASCII hex big-endian fields, name NUL-
/// terminated, name+header padded to 4, data padded to 4.
/// Fixed boot-image timestamp (2026-10-12 UTC) so ls -l shows a sane
/// date for packed files; runtime writes use the kernel clock.
const BOOT_MTIME: i64 = 1_791_763_200;

fn pack_newc(entries: &[CpioEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut ino = 1u32;
    for e in entries {
        write_newc(&mut out, ino, e.mode, &e.name, e.data, BOOT_MTIME);
        ino += 1;
    }
    // Trailer.
    write_newc(&mut out, 0, 0, "TRAILER!!!", &[], 0);
    while out.len() % 512 != 0 {
        out.push(0);
    }
    // 64 KiB headroom: QEMU capacity == file size, so runtime-created
    // entries need reserved space (the parser stops at TRAILER!!!,
    // making the zero tail invisible to readers).
    out.resize(out.len() + 64 * 1024, 0);
    out
}

fn write_newc(out: &mut Vec<u8>, ino: u32, mode: u32, name: &str, data: &[u8], mtime: i64) {
    let name_bytes = name.as_bytes();
    let namesize = name_bytes.len() + 1; // includes NUL
    let mut hdr = String::with_capacity(110);
    hdr.push_str("070701");
    for v in [
        ino,
        mode,
        0, // uid
        0, // gid
        1, // nlink
        mtime as u32,
        data.len() as u32,
        0, // devmajor
        0, // devminor
        0, // rdevmajor
        0, // rdevminor
        namesize as u32,
        0, // check
    ] {
        hdr.push_str(&format!("{v:08x}"));
    }
    debug_assert_eq!(hdr.len(), 110);
    out.extend_from_slice(hdr.as_bytes());
    out.extend_from_slice(name_bytes);
    out.push(0);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

/// Generate `$SYSNAME` constants for the NetBSD personality from NetBSD's
/// own `sys/kern/syscalls.master`, the same file NetBSD's `makesyscalls.sh`
/// consumes. Hand-transcribing the numbers would silently diverge from the
/// compat_09..compat_110 layers; generating them keeps every dispatched
/// number traceable to its upstream revision.
///
/// The table is BSD 4-clause (Christoph Demetriou, 1994/1996/2000); its
/// attribution lives in assets/bsd/THIRD-PARTY.txt.
fn gen_netbsd_syscall_table(dir: &str, out: &str) {
    let master = std::path::Path::new(dir).join("assets/bsd/syscalls.master");
    println!("cargo:rerun-if-changed=assets/bsd/syscalls.master");
    let text = std::fs::read_to_string(&master)
        .unwrap_or_else(|e| panic!("read {}: {e}", master.display()));

    // Keep the CVS id so every generated number carries its provenance.
    let cvs = text
        .lines()
        .find(|l| l.contains("NetBSD:") && l.contains("syscalls.master"))
        .unwrap_or("unknown revision")
        .trim()
        .to_string();

    let mut out_rs = String::new();
    // `#![allow]` must precede every item, so it goes first.
    out_rs.push_str("// @generated from kernel/assets/bsd/syscalls.master\n");
    out_rs.push_str(&format!("// upstream: {cvs}\n"));
    out_rs.push_str(
        "//\n// NetBSD BSD 4-clause; attribution in kernel/assets/bsd/THIRD-PARTY.txt.\n\
         // Do not edit -- regenerate via build.rs.\n\n\
         pub mod nr {\n",
    );

    let mut count = 0usize;
    // A name can recur across compat layers (getsockname, setrlimit and
    // reboot all do). First definition wins the bare name; later ones get a
    // numeric suffix so nothing is silently dropped.
    let mut seen: Vec<String> = Vec::new();
    // Entries wrap with a trailing backslash, so join continuations before
    // parsing or every wrapped prototype is silently skipped.
    let mut joined: Vec<String> = Vec::new();
    let mut pending = String::new();
    for raw in text.lines() {
        let l = raw.trim_end();
        if let Some(head) = l.strip_suffix('\\') {
            pending.push_str(head);
            pending.push(' ');
        } else {
            // Continuation and its terminator form ONE entry: joining must
            // concatenate, not push two elements (splitting them loses the
            // prototype that carries the syscall name).
            let joined_line = std::mem::take(&mut pending);
            joined.push(format!("{joined_line}{l}"));
        }
    }
    joined.push(pending);
    for line in joined.iter().map(|s| s.as_str()) {
        // Entries look like:  <number>\t<TYPE>\t... { <ret>|sys||<name>(...); }
        // but compat entries carry a revision field too:
        //   293 STD  { int|sys|14|sigprocmask(...); }
        // so the name is the token after the LAST "|" that precedes it,
        // not blindly the second "||" field. Skip comments, blanks, and
        // the C preamble above the first numbered entry.
        let mut it = line.splitn(2, '\t');
        let Some(num) = it.next() else { continue };
        let Some(rest) = it.next() else { continue };
        let num: u32 = match num.trim().parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        // Take the identifier immediately before the first '(' in the
        // prototype, e.g. "{ int|sys|14|sigprocmask(int how, ...); }"
        // yields "sigprocmask".
        let name = rest
            .split_once('{')
            .map(|(_, proto)| proto)
            .unwrap_or(rest)
            .split_once('(')
            .map(|(head, _)| head)
            .unwrap_or("")
            .rsplit('|')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let base: &str = &name;
        let name = if seen.iter().any(|s| s == base) {
            let mut n = 2;
            loop {
                let cand = format!("{base}__{n}");
                if !seen.iter().any(|s| *s == cand) {
                    break cand;
                }
                n += 1;
            }
        } else {
            base.to_string()
        };
        seen.push(name.clone());
        // syscalls.master names are lowercase (NetBSD's own convention);
        // emit SCREAMING_CASE to match this tree's constants and avoid
        // non_upper_case_globals, which is a warning here.
        let ident = name.to_uppercase();
        // Keep the upstream spelling in the doc comment: the constant is
        // SCREAMING_CASE, but the number must stay traceable to the row in
        // syscalls.master that produced it.
        out_rs.push_str(&format!(
            "    /// NetBSD `{name}`.\n    pub const {ident}: u16 = {num};\n"
        ));
        count += 1;
    }
    out_rs.push_str("}\n");

    let dest = std::path::Path::new(out).join("netbsd_syscall_table.rs");
    std::fs::write(&dest, out_rs)
        .unwrap_or_else(|e| panic!("write {}: {e}", dest.display()));
    println!("cargo:rustc-env=NETBSD_SYSCALL_COUNT={count}");
}
