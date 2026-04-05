#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo ./install-service.sh [--cert <path>] [--key <path>] [--name <service>] [--python <python-bin>]"
  exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_OWNER="$(stat -c %U "${REPO_DIR}")"

TARGET_DIR="/etc/novncext"
SERVICE_NAME="novncext.service"
CERT_SRC="certs/server.cert.pem"
KEY_SRC="certs/server.key.pem"
PYTHON_BIN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cert)
      CERT_SRC="$2"
      shift 2
      ;;
    --key)
      KEY_SRC="$2"
      shift 2
      ;;
    --name)
      SERVICE_NAME="$2"
      shift 2
      ;;
    --python)
      PYTHON_BIN="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1"
      exit 1
      ;;
  esac
done

if [[ "${CERT_SRC}" != /* ]]; then
  CERT_SRC="${REPO_DIR}/${CERT_SRC}"
fi
if [[ "${KEY_SRC}" != /* ]]; then
  KEY_SRC="${REPO_DIR}/${KEY_SRC}"
fi

[[ -f "${REPO_DIR}/app.py" ]] || { echo "Missing app.py in ${REPO_DIR}"; exit 1; }
[[ -f "${REPO_DIR}/requirements.txt" ]] || { echo "Missing requirements.txt in ${REPO_DIR}"; exit 1; }
[[ -f "${REPO_DIR}/xstartup.novncext.sh" ]] || { echo "Missing xstartup.novncext.sh in ${REPO_DIR}"; exit 1; }
[[ -d "${REPO_DIR}/static" ]] || { echo "Missing static directory in ${REPO_DIR}"; exit 1; }
[[ -d "${REPO_DIR}/bin" ]] || { echo "Missing bin directory in ${REPO_DIR}"; exit 1; }
[[ -f "${CERT_SRC}" ]] || { echo "Cert file not found: ${CERT_SRC}"; exit 1; }
[[ -f "${KEY_SRC}" ]] || { echo "Key file not found: ${KEY_SRC}"; exit 1; }

if [[ -z "${PYTHON_BIN}" ]]; then
  USER_PYENV_PY="/home/${REPO_OWNER}/.pyenv/versions/novncext-venv/bin/python"
  USER_PYENV_BIN="/home/${REPO_OWNER}/.pyenv/bin/pyenv"
  if [[ -x "${USER_PYENV_PY}" ]]; then
    PYTHON_BIN="${USER_PYENV_PY}"
  elif [[ -x "${USER_PYENV_BIN}" ]]; then
    PYTHON_BIN="$(PYENV_ROOT="/home/${REPO_OWNER}/.pyenv" "${USER_PYENV_BIN}" which python || true)"
  fi
fi
if [[ -z "${PYTHON_BIN}" || ! -x "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="/usr/bin/python3"
fi

install -d -m 755 "${TARGET_DIR}"
install -d -m 755 "${TARGET_DIR}/static"
rm -rf "${TARGET_DIR}/bin"
install -d -m 755 "${TARGET_DIR}/bin"
install -d -m 755 "${TARGET_DIR}/certs"

install -m 644 "${REPO_DIR}/app.py" "${TARGET_DIR}/app.py"
install -m 644 "${REPO_DIR}/requirements.txt" "${TARGET_DIR}/requirements.txt"
install -m 755 "${REPO_DIR}/xstartup.novncext.sh" "${TARGET_DIR}/xstartup.novncext.sh"
cp -a "${REPO_DIR}/static/." "${TARGET_DIR}/static/"
cp -a "${REPO_DIR}/bin/." "${TARGET_DIR}/bin/"

install -m 644 "${CERT_SRC}" "${TARGET_DIR}/certs/server.cert.pem"
install -m 600 "${KEY_SRC}" "${TARGET_DIR}/certs/server.key.pem"

if [[ -d "${TARGET_DIR}/.venv" ]]; then
  rm -rf "${TARGET_DIR}/.venv"
fi
"${PYTHON_BIN}" -m venv "${TARGET_DIR}/.venv"
"${TARGET_DIR}/.venv/bin/pip" install --upgrade pip >/dev/null
"${TARGET_DIR}/.venv/bin/pip" install -r "${TARGET_DIR}/requirements.txt"

UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}"
cat > "${UNIT_PATH}" <<EOF
[Unit]
Description=TurboVNC HTTPS Session Manager (noVNC)
After=network.target

[Service]
Type=simple
WorkingDirectory=${TARGET_DIR}
ExecStart=${TARGET_DIR}/.venv/bin/python ${TARGET_DIR}/app.py --cert ${TARGET_DIR}/certs/server.cert.pem --key ${TARGET_DIR}/certs/server.key.pem --port 3389
Restart=always
RestartSec=2
User=root
Group=root
Environment=PYTHONUNBUFFERED=1
Environment=NOVNCEXT_XSTARTUP=${TARGET_DIR}/xstartup.novncext.sh

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

echo "Installed and started ${SERVICE_NAME}"
echo "Runtime directory: ${TARGET_DIR}"
echo "Status: systemctl status ${SERVICE_NAME} --no-pager"
echo "Logs: journalctl -u ${SERVICE_NAME} -f"
