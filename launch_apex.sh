#!/usr/bin/env bash
set -euo pipefail

SOURCE_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "${SOURCE_PATH}")" && pwd)"

if [[ -n "${SNAP:-}" || "${GIO_MODULE_DIR:-}" == *"/snap/"* || "${GTK_PATH:-}" == *"/snap/"* ]]; then
    unset GSETTINGS_SCHEMA_DIR GTK_PATH GIO_MODULE_DIR LD_LIBRARY_PATH GTK_EXE_PREFIX GTK_DATA_PREFIX
    export XDG_DATA_DIRS="/usr/local/share:/usr/share:/var/lib/snapd/desktop"
fi

cd "${SCRIPT_DIR}"
exec python3 "${SCRIPT_DIR}/apex_gtk_app.py" "$@"


