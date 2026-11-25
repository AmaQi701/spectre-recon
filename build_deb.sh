#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="/tmp/apex_deb_build"
DIST_DIR="${ROOT_DIR}/dist"

rm -rf "${PKG_DIR}"
mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/opt/apex-asm-studio"
mkdir -p "${PKG_DIR}/usr/local/bin"
mkdir -p "${PKG_DIR}/usr/share/applications"
mkdir -p "${DIST_DIR}"

cat << 'EOF' > "${PKG_DIR}/DEBIAN/control"
Package: spectre-recon
Version: 8.4.0
Section: utils
Priority: optional
Architecture: amd64
Depends: python3, python3-gi, gir1.2-gtk-3.0, python3-requests, python3-yaml, python3-dnspython, python3-bs4, libssl3 | libssl1.1
Recommends: g++, rustc, libssl-dev, nmap, whois, dnsutils
Maintainer: AmaQi701 <67887617+AmaQi701@users.noreply.github.com>
Description: SPECTRE Polyglot C++17/Rust/Python Attack Surface & Security Audit Studio
 Native Linux GTK3 & Headless CLI platform with C++17 v4 epoll/OpenSSL & Rust FFI kernels,
 250 declarative NVTs, 50 socket verifiers, 250 CPEs, AI/MCP auditor, 6-lang SAST, Cloud/IaC v3, 18-format SCA, and 7-Framework (+MITRE v15) Compliance.
EOF

if command -v g++ >/dev/null 2>&1; then
    g++ -O3 -std=c++17 -shared -fPIC "${ROOT_DIR}/core/native/spectre_accel.cpp" -o "${ROOT_DIR}/core/native/libspectre_accel.so" -lssl -lcrypto
fi

RUSTC_BIN="$(command -v rustc || true)"
if [ -z "${RUSTC_BIN}" ] && [ -x "${HOME}/.cargo/bin/rustc" ]; then
    RUSTC_BIN="${HOME}/.cargo/bin/rustc"
fi
if [ -n "${RUSTC_BIN}" ]; then
    "${RUSTC_BIN}" -C opt-level=3 -C strip=debuginfo --crate-type cdylib "${ROOT_DIR}/core/native/spectre_rust_core.rs" -o "${ROOT_DIR}/core/native/libspectre_rust_core.so"
fi

cp -r "${ROOT_DIR}/agents" "${ROOT_DIR}/config" "${ROOT_DIR}/core" "${ROOT_DIR}/ui" "${ROOT_DIR}/apex_gtk_app.py" "${ROOT_DIR}/spectre_cli.py" "${ROOT_DIR}/launch_apex.sh" "${PKG_DIR}/opt/apex-asm-studio/"
find "${PKG_DIR}/opt/apex-asm-studio" -name "__pycache__" -exec rm -rf {} +
mkdir -p "${PKG_DIR}/opt/apex-asm-studio/workspaces" "${PKG_DIR}/opt/apex-asm-studio/reports"
chmod 755 "${PKG_DIR}/opt/apex-asm-studio/launch_apex.sh" "${PKG_DIR}/opt/apex-asm-studio/apex_gtk_app.py" "${PKG_DIR}/opt/apex-asm-studio/spectre_cli.py"

ln -sf /opt/apex-asm-studio/launch_apex.sh "${PKG_DIR}/usr/local/bin/spectre-recon"
ln -sf /opt/apex-asm-studio/spectre_cli.py "${PKG_DIR}/usr/local/bin/spectre-cli"

cat << 'EOF' > "${PKG_DIR}/usr/share/applications/spectre-recon.desktop"
[Desktop Entry]
Version=1.0
Type=Application
Name=SPECTRE Recon Studio
GenericName=Cyber-Recon & Attack Surface Studio
Comment=SPECTRE v8.4.0 Polyglot C++17/Rust/Python ASM, 250-NVT, 50-Port Socket NVT, AI/MCP/RAG, 6-Lang SAST & 7-Framework Studio
Exec=/bin/bash /opt/apex-asm-studio/launch_apex.sh
Path=/opt/apex-asm-studio
Icon=/opt/apex-asm-studio/ui/apex-icon.svg
Terminal=false
Categories=Utility;Security;Development;System;
Keywords=pentest;recon;security;audit;spectre;scanner;
StartupNotify=true
EOF

dpkg-deb --root-owner-group --build "${PKG_DIR}" "${DIST_DIR}/spectre-recon_8.4.0_amd64.deb"
echo "[+] Built package: ${DIST_DIR}/spectre-recon_8.4.0_amd64.deb"
