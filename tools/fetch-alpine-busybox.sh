#!/usr/bin/env bash
# Fetch Alpine's static busybox (aarch64) into .toolchain/alpine/.
# The .apk is a tar.gz with a leading signature member; extraction skips it.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/.toolchain/alpine"
OUT="$DEST/busybox"

if [ -x "$OUT" ]; then
    echo "busybox present: $OUT"
    "$OUT" | head -1 || true
    exit 0
fi
mkdir -p "$DEST"

# Versioned filename (Alpine CDN has no unversioned alias).
VER="${ALPINE_BUSYBOX_VER:-1.36.1-r31}"
URL="https://dl-cdn.alpinelinux.org/alpine/v3.20/main/aarch64/busybox-static-${VER}.apk"
APK="$DEST/busybox-static-${VER}.apk"
if [ ! -f "$APK" ]; then
    echo "downloading $URL ..."
    curl -fL --retry 3 -o "$APK" "$URL"
fi

python3 - "$APK" "$OUT" <<'PY'
import gzip, io, sys, tarfile
apk, out = sys.argv[1], sys.argv[2]
data = open(apk, "rb").read()
# apk v2: signature member then one or more gzip streams; find first gzip magic.
i = data.find(b"\x1f\x8b\x08")
if i < 0:
    sys.exit("no gzip stream in apk")
tf = tarfile.open(fileobj=io.BytesIO(gzip.decompress(data)), mode="r:") if i == 0 else tarfile.open(fileobj=io.BytesIO(gzip.decompress(data[i:])), mode="r:")
for m in tf.getmembers():
    if m.name.lstrip("./") in ("bin/busybox.static", "bin/busybox", "usr/bin/busybox"):
        f = tf.extractfile(m)
        open(out, "wb").write(f.read())
        print(f"extracted {m.name} -> {out} ({m.size} bytes)")
        break
else:
    sys.exit("busybox not found in apk")
PY
chmod +x "$OUT"
"$OUT" | head -1 || true
echo "busybox ready"
