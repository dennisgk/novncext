#!/bin/sh
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ -d "${script_dir}/bin" ]; then
  export PATH="${script_dir}/bin:${PATH}"
fi

prepare_snap_wrappers() {
  [ -d /snap/bin ] || return 0
  [ -x "${script_dir}/bin/snap-app-run" ] || return 0

  wrap_dir="${HOME}/.cache/novncext/snap-wrap"
  mkdir -p "${wrap_dir}"

  for snap_bin in /snap/bin/*; do
    [ -e "${snap_bin}" ] || continue
    app_name="$(basename "${snap_bin}")"
    wrapper="${wrap_dir}/${app_name}"
    cat > "${wrapper}" <<EOF
#!/usr/bin/env bash
exec "${script_dir}/bin/snap-app-run" "${app_name}" "\$@"
EOF
    chmod 755 "${wrapper}"
  done

  export PATH="${wrap_dir}:${PATH}"
}

prepare_snap_desktop_overrides() {
  src_dir="/var/lib/snapd/desktop/applications"
  [ -d "${src_dir}" ] || return 0

  dst_dir="${HOME}/.local/share/applications"
  mkdir -p "${dst_dir}"

  for src in "${src_dir}"/*.desktop; do
    [ -f "${src}" ] || continue
    base="$(basename "${src}")"
    dst="${dst_dir}/${base}"
    # Force desktop launches to use command names (resolved via PATH wrappers)
    # instead of absolute /snap/bin or /usr/bin/snap run paths.
    sed -E \
      -e 's#^Exec=.* /snap/bin/([^[:space:]]+)(.*)$#Exec=\1\2#' \
      -e 's#^Exec=/snap/bin/([^[:space:]]+)(.*)$#Exec=\1\2#' \
      -e 's#^Exec=.* /usr/bin/snap run ([^[:space:]]+)(.*)$#Exec=\1\2#' \
      -e 's#^Exec=/usr/bin/snap run ([^[:space:]]+)(.*)$#Exec=\1\2#' \
      "${src}" > "${dst}"
  done
}

uid="$(id -u)"
runtime_dir="/run/user/${uid}"

if [ -d "${runtime_dir}" ]; then
  export XDG_RUNTIME_DIR="${runtime_dir}"
fi

# Prefer the user systemd session bus so snap apps can track/attach scopes.
bus_socket="${runtime_dir}/bus"
if [ -S "${bus_socket}" ]; then
  export DBUS_SESSION_BUS_ADDRESS="unix:path=${bus_socket}"
  export TVNC_USERDBUS=1
else
  unset DBUS_SESSION_BUS_ADDRESS
  unset TVNC_USERDBUS
fi

# Suppress noisy AT-SPI bridge warnings in headless/remote VNC sessions.
# This disables desktop accessibility bridge initialization for that session.
export NO_AT_BRIDGE=1
export GTK_A11Y=none
export QT_LINUX_ACCESSIBILITY_ALWAYS_ON=0

prepare_snap_wrappers
prepare_snap_desktop_overrides

# Run the desktop in its own DBus session so multiple VNC desktops for the
# same Linux user do not collide on singleton XFCE/autostart components.
if command -v dbus-run-session >/dev/null 2>&1; then
  exec dbus-run-session -- /opt/TurboVNC/bin/xstartup.turbovnc
fi

exec /opt/TurboVNC/bin/xstartup.turbovnc
