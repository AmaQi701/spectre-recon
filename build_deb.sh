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
Version: 3.3.0
Section: utils
Priority: optional
Architecture: amd64
Depends: python3, python3-gi, gir1.2-gtk-3.0, python3-requests, python3-yaml, python3-dnspython, python3-bs4, libssl3 | libssl1.1
Recommends: g++, libssl-dev, nmap, whois, dnsutils
Maintainer: AmaQi701 <67887617+AmaQi701@users.noreply.github.com>
Description: SPECTRE Hybrid C++17/Python Attack Surface & Security Audit Studio
 Native Linux GTK3 Desktop platform with C++17 epoll/OpenSSL acceleration,
 active protocol NVTs, 68-product CPE 2.3 engine, and CISA KEV correlation.
EOF

if command -v g++ >/dev/null 2>&1; then
    g++ -O3 -std=c++17 -shared -fPIC "${ROOT_DIR}/core/native/spectre_accel.cpp" -o "${ROOT_DIR}/core/native/libspectre_accel.so" -lssl -lcrypto
fi

cp -r "${ROOT_DIR}/agents" "${ROOT_DIR}/config" "${ROOT_DIR}/core" "${ROOT_DIR}/ui" "${ROOT_DIR}/apex_gtk_app.py" "${ROOT_DIR}/launch_apex.sh" "${PKG_DIR}/opt/apex-asm-studio/"
find "${PKG_DIR}/opt/apex-asm-studio" -name "__pycache__" -exec rm -rf {} +
mkdir -p "${PKG_DIR}/opt/apex-asm-studio/workspaces" "${PKG_DIR}/opt/apex-asm-studio/reports"
chmod 755 "${PKG_DIR}/opt/apex-asm-studio/launch_apex.sh" "${PKG_DIR}/opt/apex-asm-studio/apex_gtk_app.py"

ln -sf /opt/apex-asm-studio/launch_apex.sh "${PKG_DIR}/usr/local/bin/spectre-recon"

cat << 'EOF' > "${PKG_DIR}/usr/share/applications/spectre-recon.desktop"
[Desktop Entry]
Version=1.0
Type=Application
Name=SPECTRE Recon Studio
GenericName=Cyber-Recon & Attack Surface Studio
Comment=SPECTRE v3.3.0 Hybrid C++17/Python Recon, Protocol NVT, Bug Chaining & Report Studio
Exec=/bin/bash /opt/apex-asm-studio/launch_apex.sh
Path=/opt/apex-asm-studio
Icon=/opt/apex-asm-studio/ui/apex-icon.svg
Terminal=false
Categories=Utility;Security;Development;System;
Keywords=pentest;recon;security;audit;spectre;scanner;
StartupNotify=true
EOF

dpkg-deb --root-owner-group --build "${PKG_DIR}" "${DIST_DIR}/spectre-recon_3.3.0_amd64.deb"
echo "[+] Built package: ${DIST_DIR}/spectre-recon_3.3.0_amd64.deb"
