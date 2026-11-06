#!/usr/bin/env bash
unset GSETTINGS_SCHEMA_DIR GTK_PATH GIO_MODULE_DIR LD_LIBRARY_PATH GTK_EXE_PREFIX GTK_DATA_PREFIX
export XDG_DATA_DIRS="/usr/local/share:/usr/share:/var/lib/snapd/desktop"
cd /home/amaqi/projects/apex-pentest-gui
exec /usr/bin/python3 /home/amaqi/projects/apex-pentest-gui/apex_gtk_app.py "$@"


