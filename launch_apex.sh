#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
unset GSETTINGS_SCHEMA_DIR GTK_PATH GIO_MODULE_DIR LD_LIBRARY_PATH GTK_EXE_PREFIX GTK_DATA_PREFIX
export XDG_DATA_DIRS="/usr/local/share:/usr/share:/var/lib/snapd/desktop"
cd "${SCRIPT_DIR}"
exec python3 "${SCRIPT_DIR}/apex_gtk_app.py" "$@"

