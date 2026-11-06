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
Package: apex-asm-studio
Version: 2.0
Section: utils
Priority: optional
Architecture: all
Depends: python3, python3-gi, gir1.2-gtk-3.0, python3-requests, python3-yaml, python3-dnspython, python3-bs4
Maintainer: AmaQi701 <67887617+AmaQi701@users.noreply.github.com>
Description: Autonomous Recon, Vulnerability Assessment, Bug Chaining & Report Studio
 Native Ubuntu GTK3 Desktop platform for authorized penetration testing and ASM.
EOF

cp -r "${ROOT_DIR}/agents" "${ROOT_DIR}/config" "${ROOT_DIR}/core" "${ROOT_DIR}/ui" "${ROOT_DIR}/apex_gtk_app.py" "${ROOT_DIR}/app.py" "${ROOT_DIR}/launch_apex.sh" "${PKG_DIR}/opt/apex-asm-studio/"
mkdir -p "${PKG_DIR}/opt/apex-asm-studio/workspaces" "${PKG_DIR}/opt/apex-asm-studio/reports"
chmod 755 "${PKG_DIR}/opt/apex-asm-studio/launch_apex.sh" "${PKG_DIR}/opt/apex-asm-studio/apex_gtk_app.py"

ln -sf /opt/apex-asm-studio/launch_apex.sh "${PKG_DIR}/usr/local/bin/apex-asm-studio"

cat << 'EOF' > "${PKG_DIR}/usr/share/applications/apex-pentest.desktop"
[Desktop Entry]
Version=1.0
Type=Application
Name=APEX-ASM Pentest Studio
GenericName=Pentest & Security Audit GUI
Comment=Autonomous Recon, Vulnerability Assessment, Bug Chaining & Report Studio
Exec=/bin/bash /opt/apex-asm-studio/launch_apex.sh
Path=/opt/apex-asm-studio
Icon=/opt/apex-asm-studio/ui/apex-icon.svg
Terminal=false
Categories=Utility;Security;Development;System;
Keywords=pentest;recon;security;audit;apex;scanner;
StartupNotify=true
EOF

dpkg-deb --root-owner-group --build "${PKG_DIR}" "${DIST_DIR}/apex-asm-studio_2.0_all.deb"
echo "[+] Built package: ${DIST_DIR}/apex-asm-studio_2.0_all.deb"
