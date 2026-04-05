#!/bin/sh
set -eu

uid="$(id -u)"
runtime_dir="/run/user/${uid}"

if [ -d "${runtime_dir}" ]; then
  export XDG_RUNTIME_DIR="${runtime_dir}"
fi

if [ -S "${runtime_dir}/bus" ]; then
  export DBUS_SESSION_BUS_ADDRESS="unix:path=${runtime_dir}/bus"
  export TVNC_USERDBUS=1
fi

# Suppress noisy AT-SPI bridge warnings in headless/remote VNC sessions.
# This disables desktop accessibility bridge initialization for that session.
export NO_AT_BRIDGE=1
export GTK_A11Y=none
export QT_LINUX_ACCESSIBILITY_ALWAYS_ON=0

exec /opt/TurboVNC/bin/xstartup.turbovnc
