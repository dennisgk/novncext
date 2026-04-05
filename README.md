# TurboVNC HTTPS Session Manager

Python web server for TurboVNC sessions with:

- HTTPS only on port `3389`
- Session list at `/`
- Create/delete named sessions
- Join session at `/sessions/<name>/view` using noVNC in-browser
- Built-in websocket proxy (`/sessions/<name>/ws`) as a websockify analog

## Setup

```bash
cd /home/oem/novncext
~/.pyenv/bin/pyenv virtualenv -f system novncext-venv
echo "novncext-venv" > .python-version
~/.pyenv/bin/pyenv exec pip install -r requirements.txt
```

## Use Your Own SSL Certificate

Example self-signed cert generation (replace with your real cert as needed):

```bash
mkdir -p certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -subj "/CN=localhost"
```

## Run

```bash
cd /home/oem/novncext
sudo ~/.pyenv/bin/pyenv exec python app.py \
  --cert /absolute/path/to/cert.pem \
  --key /absolute/path/to/key.pem \
  --port 3389
```

The app rejects any port other than `3389`.

After opening the site, login with a local Linux username/password.  
Tokens are stored in app memory only, and session lists/actions are scoped to the logged-in user.

When installed via `install-service.sh`, the xstartup helper is copied to `/etc/novncext/xstartup.novncext.sh` so all local users can execute it.

## Notes

- TurboVNC sessions are started local-only (`-localhost`) and accessed through the HTTPS websocket proxy.
- Session name rules: `^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$`
- Session names are discovered from live TurboVNC/Xvnc process args (no local session state file).
