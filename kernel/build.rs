use std::path::Path;
use std::process::Command;

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-T{dir}/src/arch/link.ld");
    println!("cargo:rerun-if-changed=src/arch/link.ld");
    println!("cargo:rerun-if-changed=../user/src/main.rs");
    println!("cargo:rerun-if-changed=../user/src/greet.rs");
    println!("cargo:rerun-if-changed=../user/src/sh.rs");
    println!("cargo:rerun-if-changed=../user/user.ld");
    println!("cargo:rerun-if-changed=assets/motd");

    // Build the user programs into a private target dir (nested cargo
    // would deadlock on the parent's target-dir lock, hence OUT_DIR/user).
    let out = std::env::var("OUT_DIR").unwrap();
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
    for p in [&sh, &hello, &greet] {
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
    let src = Path::new(&dir).join("../linux/hello.c");
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
    println!("cargo:rerun-if-changed=../linux/hello.c");

    // Pack everything into a cpio newc initramfs image.
    let motd = std::fs::read(Path::new(&dir).join("assets/motd")).expect("read motd");
    let sh_bytes = std::fs::read(&sh).unwrap();
    let hello_bytes = std::fs::read(&hello).unwrap();
    let greet_bytes = std::fs::read(&greet).unwrap();
    let linux_bytes = std::fs::read(&linux_out).expect("read linux-hello");
    let entries: Vec<CpioEntry> = vec![
        CpioEntry::dir("."),
        CpioEntry::dir("bin"),
        CpioEntry::dir("etc"),
        CpioEntry::file("bin/sh", &sh_bytes),
        CpioEntry::file("bin/hello", &hello_bytes),
        CpioEntry::file("bin/greet", &greet_bytes),
        CpioEntry::file("bin/linux-hello", &linux_bytes),
        CpioEntry::file("etc/motd", &motd),
    ];
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
}

/// cpio "newc": 110-byte header, ASCII hex big-endian fields, name NUL-
/// terminated, name+header padded to 4, data padded to 4.
fn pack_newc(entries: &[CpioEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut ino = 1u32;
    for e in entries {
        write_newc(&mut out, ino, e.mode, &e.name, e.data);
        ino += 1;
    }
    // Trailer.
    write_newc(&mut out, 0, 0, "TRAILER!!!", &[]);
    while out.len() % 512 != 0 {
        out.push(0);
    }
    // 64 KiB headroom: QEMU capacity == file size, so runtime-created
    // entries need reserved space (the parser stops at TRAILER!!!,
    // making the zero tail invisible to readers).
    out.resize(out.len() + 64 * 1024, 0);
    out
}

fn write_newc(out: &mut Vec<u8>, ino: u32, mode: u32, name: &str, data: &[u8]) {
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
        0, // mtime
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
