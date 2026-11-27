#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(mktemp -d -t spectre_deb_build.XXXXXX)"
trap 'rm -rf "${PKG_DIR}"' EXIT
DIST_DIR="${ROOT_DIR}/dist"

mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/opt/apex-asm-studio"
mkdir -p "${PKG_DIR}/usr/local/bin"
mkdir -p "${PKG_DIR}/usr/share/applications"
mkdir -p "${DIST_DIR}"

cat << 'EOF' > "${PKG_DIR}/DEBIAN/control"
Package: spectre-recon
Version: 9.5.0
Section: utils
Priority: optional
Architecture: amd64
Depends: python3, python3-gi, python3-gi-cairo, gir1.2-gtk-3.0, gir1.2-gdkpixbuf-2.0, python3-requests, python3-yaml, python3-dnspython, python3-bs4, libssl3t64 | libssl3 | libssl1.1
Recommends: g++, rustc, golang-go, libssl-dev, nmap, whois, dnsutils
Maintainer: AmaQi701 <67887617+AmaQi701@users.noreply.github.com>
Description: SPECTRE Polyglot C++17/Rust/Go/Python ASM & Offline Threat Intelligence Studio
 Native Linux GTK3 & Headless CLI platform with C++17 v5, Rust FFI & Go Goroutine kernels,
 2000 declarative NVTs, 109k+ Offline Threat Intel DB (CISA KEV, IEEE OUI, PSL, Favicon MMH3),
 402k+ MIT SecLists discovery wordlists, 50 socket verifiers, 6-lang SAST, and 7-Framework Compliance.
EOF

g++ -O3 -Wall -Wextra -D_FORTIFY_SOURCE=2 -fstack-protector-strong -std=c++17 -shared -fPIC -pthread "${ROOT_DIR}"/core/native/*.cpp -o "${ROOT_DIR}/core/native/libspectre_accel.so" -lssl -lcrypto

RUSTC_BIN="$(command -v rustc || true)"
if [ -z "${RUSTC_BIN}" ] && [ -x "${HOME}/.cargo/bin/rustc" ]; then
    RUSTC_BIN="${HOME}/.cargo/bin/rustc"
fi
[ -n "${RUSTC_BIN}" ]
"${RUSTC_BIN}" -C opt-level=3 -C strip=debuginfo --crate-type cdylib "${ROOT_DIR}/core/native/spectre_rust_core.rs" -o "${ROOT_DIR}/core/native/libspectre_rust_core.so"

GO_BIN="$(command -v go || true)"
[ -n "${GO_BIN}" ]
(cd "${ROOT_DIR}/core/native" && "${GO_BIN}" build -ldflags="-s -w" -o "${ROOT_DIR}/core/native/spectre-intel-indexer" *.go)

python3 "${ROOT_DIR}/spectre_cli.py" --rebuild-intel >/dev/null

cp -r "${ROOT_DIR}/agents" "${ROOT_DIR}/config" "${ROOT_DIR}/core" "${ROOT_DIR}/intel" "${ROOT_DIR}/plugins" "${ROOT_DIR}/ui" "${ROOT_DIR}/LICENSE" "${ROOT_DIR}/THIRD_PARTY_LICENSES.md" "${ROOT_DIR}/apex_gtk_app.py" "${ROOT_DIR}/spectre_cli.py" "${ROOT_DIR}/launch_apex.sh" "${PKG_DIR}/opt/apex-asm-studio/"
find "${PKG_DIR}/opt/apex-asm-studio" -name "__pycache__" -exec rm -rf {} +
find "${PKG_DIR}/opt/apex-asm-studio" -type d -exec chmod 755 {} +
find "${PKG_DIR}/opt/apex-asm-studio" -type f -exec chmod 644 {} +
mkdir -p "${PKG_DIR}/opt/apex-asm-studio/workspaces" "${PKG_DIR}/opt/apex-asm-studio/reports"
chmod 755 "${PKG_DIR}/opt/apex-asm-studio/launch_apex.sh" "${PKG_DIR}/opt/apex-asm-studio/apex_gtk_app.py" "${PKG_DIR}/opt/apex-asm-studio/spectre_cli.py" "${PKG_DIR}/opt/apex-asm-studio/core/native/spectre-intel-indexer"

ln -sf /opt/apex-asm-studio/launch_apex.sh "${PKG_DIR}/usr/local/bin/spectre-recon"
ln -sf /opt/apex-asm-studio/spectre_cli.py "${PKG_DIR}/usr/local/bin/spectre-cli"

cat << 'EOF' > "${PKG_DIR}/usr/share/applications/spectre-recon.desktop"
[Desktop Entry]
Version=1.0
Type=Application
Name=SPECTRE Recon Studio
GenericName=Cyber-Recon & Attack Surface Studio
Comment=SPECTRE v9.5.0 Polyglot Rust/Go/C++17/Python ASM, Offline Threat Intel Pack, 2000-NVT, 50-Port Socket NVT & 7-Framework Studio
Exec=/bin/bash /opt/apex-asm-studio/launch_apex.sh
Path=/opt/apex-asm-studio
Icon=/opt/apex-asm-studio/ui/apex-icon.svg
Terminal=false
Categories=Utility;Security;Development;System;
Keywords=pentest;recon;security;audit;spectre;scanner;
StartupNotify=true
EOF

dpkg-deb --root-owner-group --build "${PKG_DIR}" "${DIST_DIR}/spectre-recon_9.5.0_amd64.deb"
echo "[+] Built package: ${DIST_DIR}/spectre-recon_9.5.0_amd64.deb"
