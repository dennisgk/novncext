#!/usr/bin/env python3
import argparse
import asyncio
import contextlib
import crypt
import hmac
import html
import os
import pwd
import re
import secrets
import ssl
import time
import spwd
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote

from aiohttp import web, WSMsgType

APP_PORT = 3389
SESSION_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$")
TURBOVNC_BIN = Path("/opt/TurboVNC/bin/vncserver")
XSTARTUP_SCRIPT = Path(os.environ.get("NOVNCEXT_XSTARTUP", str(Path(__file__).with_name("xstartup.novncext.sh"))))
SESSION_COOKIE = "novncext_token"
TOKENS: Dict[str, str] = {}


def run_cmd(args: List[str], env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=False, env=env)


def user_exists(username: str) -> bool:
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False


def verify_system_password(username: str, password: str) -> bool:
    try:
        shadow = spwd.getspnam(username).sp_pwdp
    except (KeyError, PermissionError):
        return False

    if not shadow or shadow.startswith("!") or shadow.startswith("*"):
        return False
    return hmac.compare_digest(crypt.crypt(password, shadow), shadow)


def issue_token(username: str) -> str:
    token = secrets.token_urlsafe(32)
    TOKENS[token] = username
    return token


def username_from_token(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    return TOKENS.get(token)


def run_as_user_args(username: str, args: List[str]) -> List[str]:
    if os.geteuid() == 0 and Path("/usr/sbin/runuser").exists():
        return ["/usr/sbin/runuser", "-u", username, "--", *args]
    return ["sudo", "-n", "-H", "-u", username, *args]


def vnc_log_tail(username: str, display: int, lines: int = 40) -> str:
    try:
        home = pwd.getpwnam(username).pw_dir
    except KeyError:
        return ""
    log_path = Path(home) / ".vnc" / f"{os.uname().nodename}:{display}.log"
    if not log_path.exists():
        return ""
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return "\n".join(text.splitlines()[-lines:])


def xsession_errors_tail(username: str, lines: int = 80) -> str:
    try:
        home = pwd.getpwnam(username).pw_dir
    except KeyError:
        return ""

    chunks: List[str] = []
    for fname in (".xsession-errors", ".xsession-errors.old"):
        path = Path(home) / fname
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        tail = "\n".join(text.splitlines()[-lines:])
        if tail.strip():
            chunks.append(f"== {path} (tail) ==\n{tail}")
    return "\n\n".join(chunks)


def ensure_user_runtime(username: str) -> None:
    """Best-effort setup of /run/user/<uid> and per-user DBus runtime."""
    if os.geteuid() != 0:
        return

    user = pwd.getpwnam(username)
    uid = user.pw_uid
    gid = user.pw_gid
    runtime_dir = Path(f"/run/user/{uid}")
    bus_path = runtime_dir / "bus"

    if Path("/usr/bin/loginctl").exists():
        run_cmd(["/usr/bin/loginctl", "enable-linger", username])
    if Path("/usr/bin/systemctl").exists():
        run_cmd(["/usr/bin/systemctl", "start", f"user@{uid}.service"])

    if not runtime_dir.exists():
        runtime_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chown(runtime_dir, uid, gid)
    os.chmod(runtime_dir, 0o700)

    # Ensure a user bus exists for TVNC_USERDBUS=1 path.
    if not bus_path.exists():
        run_cmd(
            run_as_user_args(
                username,
                [
                    "dbus-daemon",
                    "--session",
                    f"--address=unix:path={bus_path}",
                    "--fork",
                    "--nopidfile",
                ],
            )
        )


def build_vnc_launch_env(username: str) -> Dict[str, str]:
    env = dict(os.environ)
    uid = pwd.getpwnam(username).pw_uid
    runtime_dir = f"/run/user/{uid}"
    if os.path.isdir(runtime_dir):
        env["XDG_RUNTIME_DIR"] = runtime_dir
        bus_path = f"{runtime_dir}/bus"
        if os.path.exists(bus_path):
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus_path}"
            env["TVNC_USERDBUS"] = "1"
    return env


def list_turbovnc_sessions(username: str) -> List[Dict[str, int]]:
    proc = run_cmd(["ps", "-eo", "user:64,pid,args"])
    if proc.returncode != 0:
        return []

    sessions = []
    for raw in proc.stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        owner, pid_s, args = parts
        if owner != username:
            continue
        if "/opt/TurboVNC/bin/Xvnc" not in args:
            continue
        disp_m = re.search(r"\s:(\d+)\b", args)
        if not disp_m:
            continue
        try:
            pid = int(pid_s)
            display = int(disp_m.group(1))
        except ValueError:
            continue
        port_m = re.search(r"\s-rfbport\s+(\d+)\b", args)
        rfb_port = int(port_m.group(1)) if port_m else (5900 + display)
        sessions.append({"display": display, "pid": pid, "rfb_port": rfb_port})

    sessions.sort(key=lambda s: s["display"])
    return sessions


def read_pid_cmdline(pid: int) -> List[str]:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return []
    return [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]


def session_name_from_cmdline(pid: int, display: int) -> str:
    args = read_pid_cmdline(pid)
    explicit_name = ""
    desktop_name = ""
    for i, token in enumerate(args):
        if token == "-name" and i + 1 < len(args):
            explicit_name = args[i + 1].strip()
            break
    if SESSION_NAME_RE.match(explicit_name):
        return explicit_name

    for i, token in enumerate(args):
        if token == "-desktop" and i + 1 < len(args):
            desktop_name = args[i + 1].strip()
            break

    if desktop_name.startswith("novncext:"):
        candidate = desktop_name.split(":", 1)[1].strip()
        if SESSION_NAME_RE.match(candidate):
            return candidate

    if SESSION_NAME_RE.match(desktop_name):
        return desktop_name
    return f"display-{display}"


def list_runtime_sessions(username: str) -> List[Dict[str, object]]:
    sessions = []
    used_names = set()
    for item in list_turbovnc_sessions(username):
        display = item["display"]
        pid = item["pid"]
        name = session_name_from_cmdline(pid=pid, display=display)
        if name in used_names:
            name = f"{name}-{display}"
        used_names.add(name)
        sessions.append(
            {
                "name": name,
                "display": display,
                "pid": pid,
                "rfb_port": item["rfb_port"],
                "managed": True,
            }
        )
    sessions.sort(key=lambda r: r["display"])
    return sessions


def next_available_display(username: str) -> int:
    used = {s["display"] for s in list_turbovnc_sessions(username)}
    for display in range(1, 100):
        if Path(f"/tmp/.X{display}-lock").exists():
            continue
        if display not in used:
            return display
    raise RuntimeError("No free TurboVNC displays available in range :1-:99")


def find_display_for_name(name: str, username: str) -> Optional[int]:
    for session in list_runtime_sessions(username):
        if session["name"] == name:
            return int(session["display"])
    return None


def start_turbovnc_session(username: str, name: str, geometry: str, depth: int) -> Dict[str, object]:
    if not SESSION_NAME_RE.match(name):
        raise ValueError("Invalid session name. Use 2-64 chars: letters, numbers, '-' or '_'")

    existing_names = {session["name"] for session in list_runtime_sessions(username)}
    if name in existing_names:
        raise ValueError(f"Session '{name}' already exists")

    ensure_user_runtime(username)
    display = next_available_display(username)
    args = [
        str(TURBOVNC_BIN),
        f":{display}",
        "-name",
        name,
        "-xstartup",
        str(XSTARTUP_SCRIPT),
        "-localhost",
        "-securitytypes",
        "none",
        "-geometry",
        geometry,
        "-depth",
        str(depth),
    ]
    proc = run_cmd(run_as_user_args(username, args), env=build_vnc_launch_env(username))
    if proc.returncode != 0:
        detail_parts = []
        if proc.stdout.strip():
            detail_parts.append(f"vncserver stdout:\n{proc.stdout.strip()}")
        if proc.stderr.strip():
            detail_parts.append(f"vncserver stderr:\n{proc.stderr.strip()}")
        vtail = vnc_log_tail(username, display)
        if vtail:
            detail_parts.append(f"Recent {username} VNC log:\n{vtail}")
        xtail = xsession_errors_tail(username)
        if xtail:
            detail_parts.append(f"Recent Xsession logs:\n{xtail}")
        detail = "\n\n".join(detail_parts).strip()
        raise RuntimeError(detail or "Failed to start TurboVNC session")

    # vncserver can return before the session is stable; verify it remains alive.
    appear_deadline = time.time() + 6.0
    appeared = False
    while time.time() < appear_deadline:
        alive = False
        for session in list_runtime_sessions(username):
            if int(session["display"]) == display:
                alive = True
                break
        if alive:
            appeared = True
            break
        time.sleep(0.25)

    if not appeared:
        tail = vnc_log_tail(username, display)
        xtail = xsession_errors_tail(username)
        detail = ""
        if tail:
            detail += f"\nRecent {username} VNC log:\n{tail}"
        if xtail:
            detail += f"\nRecent Xsession logs:\n{xtail}"
        raise RuntimeError(
            f"Session '{name}' failed to appear for user '{username}' on :{display}." + detail
        )

    stable_deadline = time.time() + 8.0
    while time.time() < stable_deadline:
        alive = False
        current = None
        for session in list_runtime_sessions(username):
            if int(session["display"]) == display:
                alive = True
                current = session
                break
        if not alive:
            tail = vnc_log_tail(username, display)
            xtail = xsession_errors_tail(username)
            detail = ""
            if tail:
                detail += f"\nRecent {username} VNC log:\n{tail}"
            if xtail:
                detail += f"\nRecent Xsession logs:\n{xtail}"
            raise RuntimeError(
                f"Session '{name}' exited shortly after start for user '{username}' on :{display}." + detail
            )
        time.sleep(0.4)

    return {
        "name": str(current["name"]) if current else name,
        "display": display,
        "rfb_port": int(current["rfb_port"]) if current else (5900 + display),
    }


def stop_turbovnc_session_by_name(username: str, name: str) -> None:
    display = find_display_for_name(name, username)
    if display is None:
        raise ValueError(f"Session '{name}' not found or not running")

    proc = run_cmd(run_as_user_args(username, [str(TURBOVNC_BIN), "-kill", f":{display}"]))
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "Failed to kill TurboVNC session")

def collect_session_view(username: str) -> Dict[str, object]:
    rows = list_runtime_sessions(username)
    print(f"[novncext] list user={username} sessions={len(rows)}")
    used = {s["display"] for s in rows}
    available = [d for d in range(1, 20) if d not in used and not Path(f"/tmp/.X{d}-lock").exists()]
    return {"sessions": rows, "available_displays": available}


def base_layout(content: str, message: str = "", username: Optional[str] = None) -> str:
    escaped_message = (
        f'<div class="msg">{html.escape(message)}</div>' if message else ""
    )
    user_bar = (
        f'<div class="muted" style="margin-bottom:12px;">Signed in as <b>{html.escape(username)}</b> '
        f'| <a href="/logout" style="color:#7dd3fc;">Logout</a></div>'
        if username
        else ""
    )
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>TurboVNC Session Manager</title>
  <style>
    :root {{ --bg:#0b1320; --panel:#111c2e; --text:#e9f0fb; --muted:#9db0cc; --ok:#86efac; --warn:#fde68a; --bad:#fca5a5; --accent:#7dd3fc; }}
    * {{ box-sizing:border-box; }}
    html, body {{ min-height:100%; }}
    body {{ margin:0; min-height:100vh; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; background:
      radial-gradient(1200px 500px at 20% -10%, #173050 0%, transparent 60%),
      linear-gradient(180deg, #12243f 0%, #0b1320 48%, #060a12 100%);
      color:var(--text); }}
    .wrap {{ max-width: 1000px; margin: 32px auto; padding: 0 16px; }}
    .panel {{ background: linear-gradient(180deg, #14233a, var(--panel)); border:1px solid #2a405f; border-radius: 12px; padding:16px; margin-bottom:16px; }}
    h1 {{ margin: 0 0 8px; font-size: 24px; }}
    .muted {{ color: var(--muted); font-size: 14px; }}
    table {{ width:100%; border-collapse: collapse; margin-top:12px; }}
    th, td {{ text-align:left; padding:10px; border-bottom:1px solid #233956; font-size:14px; }}
    .msg {{ background:#10243f; border:1px solid #355f96; color:#c7ddff; padding:10px; border-radius:8px; margin-bottom:16px; }}
    .badge {{ padding:2px 8px; border-radius:20px; font-size:12px; }}
    .ok {{ background:#13361f; color:var(--ok); }}
    .warn {{ background:#3f330f; color:var(--warn); }}
    form.inline {{ display:inline; }}
    input, button {{ background:#0f1d31; color:var(--text); border:1px solid #355172; padding:8px 10px; border-radius:8px; }}
    button {{ cursor:pointer; }}
    a.button {{ display:inline-block; text-decoration:none; color:var(--text); background:#0f1d31; border:1px solid #355172; padding:8px 10px; border-radius:8px; }}
    .row {{ display:flex; gap:8px; flex-wrap:wrap; align-items:center; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>TurboVNC Session Manager</h1>
    <div class="muted">HTTPS + noVNC(websocket proxy analog) on port 3389 only</div>
    {user_bar}
    {escaped_message}
    {content}
  </div>
</body>
</html>"""


def render_login(error: str = "") -> str:
    err = f'<div class="msg">{html.escape(error)}</div>' if error else ""
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Login</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ margin:0; min-height:100vh; display:grid; place-items:center; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; background:linear-gradient(180deg,#12243f,#060a12); color:#e9f0fb; }}
    .card {{ width:min(420px,92vw); border:1px solid #2a405f; border-radius:12px; padding:18px; background:#111c2e; }}
    input, button {{ width:100%; margin-top:10px; background:#0f1d31; color:#e9f0fb; border:1px solid #355172; padding:10px; border-radius:8px; }}
    .msg {{ background:#3f1b1b; border:1px solid #7c3d3d; color:#fecaca; padding:10px; border-radius:8px; margin-top:10px; }}
  </style>
</head>
<body>
  <form class="card" method="post" action="/login">
    <h2 style="margin:0 0 8px;">Login</h2>
    <div style="color:#9db0cc;font-size:14px;">Authenticate with a local Linux user account.</div>
    <input name="username" placeholder="username" autocomplete="username" required />
    <input name="password" type="password" placeholder="password" autocomplete="current-password" required />
    <button type="submit">Sign In</button>
    {err}
  </form>
</body>
</html>"""


def render_index(username: str, message: str = "") -> str:
    data = collect_session_view(username)
    rows_html = []
    for row in data["sessions"]:
        if row["managed"]:
            name_cell = f"<code>{row['name']}</code>"
            actions = (
                f'<a class="button" href="/sessions/{row["name"]}/view">Join</a> '
                f'<form class="inline" method="post" action="/sessions/{row["name"]}/delete">'
                f'<button type="submit">Delete</button></form>'
            )
            status = '<span class="badge ok">managed</span>'
        else:
            name_cell = "<span class='muted'>unmanaged</span>"
            actions = "<span class='muted'>n/a</span>"
            status = '<span class="badge warn">external</span>'
        rows_html.append(
            "<tr>"
            f"<td>{name_cell}</td>"
            f"<td>:{row['display']}</td>"
            f"<td>{row['pid']}</td>"
            f"<td>{row['rfb_port']}</td>"
            f"<td>{status}</td>"
            f"<td>{actions}</td>"
            "</tr>"
        )
    sessions_table = (
        "<table><thead><tr><th>Name</th><th>Display</th><th>PID</th><th>RFB Port</th><th>Status</th><th>Actions</th></tr></thead><tbody>"
        + ("".join(rows_html) or "<tr><td colspan='6' class='muted'>No TurboVNC sessions running</td></tr>")
        + "</tbody></table>"
    )
    panel = f"""
<div class="panel">
  <h2>Running Sessions</h2>
  {sessions_table}
</div>
<div class="panel">
  <h2>Create Session</h2>
  <form method="post" action="/sessions/create">
    <div class="row">
      <input name="name" placeholder="unique session name" required pattern="[a-zA-Z0-9][a-zA-Z0-9_\\-]{{1,63}}" />
      <input name="geometry" value="1240x900" />
      <input name="depth" value="24" />
      <button type="submit">Add Session</button>
    </div>
  </form>
  <div class="muted">Available displays: {", ".join(f":{d}" for d in data["available_displays"])}</div>
</div>
"""
    return base_layout(panel, message=message, username=username)


@web.middleware
async def auth_middleware(request: web.Request, handler):
    path = request.path
    if path == "/login" or path.startswith("/static/"):
        return await handler(request)

    token = request.cookies.get(SESSION_COOKIE)
    username = username_from_token(token)
    if not username:
        if path.endswith("/ws"):
            raise web.HTTPUnauthorized(text="Unauthorized")
        raise web.HTTPFound("/login")
    request["auth_user"] = username
    return await handler(request)


async def login_get(request: web.Request) -> web.Response:
    token = request.cookies.get(SESSION_COOKIE)
    if username_from_token(token):
        raise web.HTTPFound("/")
    return web.Response(text=render_login(), content_type="text/html")


async def login_post(request: web.Request) -> web.StreamResponse:
    data = await request.post()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not user_exists(username):
        return web.Response(text=render_login("Invalid username or password"), content_type="text/html", status=401)
    if not verify_system_password(username, password):
        return web.Response(text=render_login("Invalid username or password"), content_type="text/html", status=401)

    token = issue_token(username)
    resp = web.HTTPFound("/")
    resp.set_cookie(SESSION_COOKIE, token, secure=True, httponly=True, samesite="Lax", path="/")
    return resp


async def logout(request: web.Request) -> web.StreamResponse:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        TOKENS.pop(token, None)
    resp = web.HTTPFound("/login")
    resp.del_cookie(SESSION_COOKIE, path="/")
    return resp


async def index(request: web.Request) -> web.Response:
    username = request["auth_user"]
    message = request.query.get("message", "")
    return web.Response(text=render_index(username, message), content_type="text/html")


async def create_session(request: web.Request) -> web.StreamResponse:
    username = request["auth_user"]
    data = await request.post()
    name = str(data.get("name", "")).strip()
    geometry = str(data.get("geometry", "1240x900")).strip()
    depth_raw = str(data.get("depth", "24")).strip()
    try:
        depth = int(depth_raw)
        if depth not in (16, 24, 32):
            raise ValueError
    except ValueError:
        return web.Response(
            text=render_index(username, "Invalid depth; must be 16, 24, or 32"),
            content_type="text/html",
            status=400,
        )

    try:
        print(f"[novncext] create requested user={username} name={name} geometry={geometry} depth={depth}")
        start_turbovnc_session(username=username, name=name, geometry=geometry, depth=depth)
    except (ValueError, RuntimeError) as exc:
        return web.Response(
            text=render_index(username, str(exc)),
            content_type="text/html",
            status=400,
        )
    raise web.HTTPFound(f"/?message={quote(f'Session {name} created', safe='')}")


async def delete_session(request: web.Request) -> web.StreamResponse:
    username = request["auth_user"]
    name = request.match_info["name"]
    try:
        stop_turbovnc_session_by_name(username, name)
    except (ValueError, RuntimeError) as exc:
        return web.Response(
            text=render_index(username, str(exc)),
            content_type="text/html",
            status=400,
        )
    raise web.HTTPFound(f"/?message={quote(f'Session {name} deleted', safe='')}")


def render_viewer(name: str) -> str:
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Session {html.escape(name)}</title>
  <style>
    html, body, #screen {{ margin:0; height:100%; background:#050b14; }}
    .settings-drawer {{ position:fixed; left:0; bottom:20px; z-index:12; font-family: ui-sans-serif, system-ui, sans-serif; width:362px; max-width:calc(100vw - 8px); height:48px; }}
    .settings-panel {{ position:absolute; left:0; bottom:0; width:320px; max-width:calc(100vw - 64px); box-sizing:border-box; border:1px solid #355f96; border-left:none; background:#0e1e34; color:#c7ddff; border-radius:0 10px 10px 0; padding:10px; transform:translateX(-100%); transition:transform 180ms ease; }}
    .settings-panel.open {{ transform:translateX(0); }}
    .settings-handle {{ position:absolute; left:0; bottom:0; width:42px; height:48px; border:1px solid #355f96; border-left:none; border-radius:0 9px 9px 0; background:#10243f; color:#c7ddff; cursor:pointer; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:5px; transition:transform 180ms ease; }}
    .settings-drawer.open .settings-handle {{ transform:translateX(320px); }}
    .settings-handle span {{ width:16px; height:2px; background:#c7ddff; display:block; }}
    .settings-row {{ display:flex; align-items:center; gap:8px; margin-bottom:8px; }}
    .settings-panel button {{ border:1px solid #355f96; background:#0f1d31; color:#c7ddff; border-radius:6px; padding:6px 8px; cursor:pointer; }}
    .settings-panel a {{ color:#7dd3fc; }}
    .status {{ font-size:12px; color:#9db0cc; min-height:1.2em; }}
    #screen {{ width:100%; height:100%; }}
  </style>
</head>
<body>
  <div class="settings-drawer">
    <div id="settingsPanel" class="settings-panel">
      <div class="settings-row"><strong>Session:</strong> <code>{html.escape(name)}</code> | <a href="/">Back</a></div>
      <label class="settings-row"><input id="optScale" type="checkbox" checked /> Scale viewport</label>
      <label class="settings-row"><input id="optResize" type="checkbox" checked /> Resize remote session</label>
      <label class="settings-row"><input id="optViewOnly" type="checkbox" /> View only</label>
      <div class="settings-row">
        <button id="pasteLocal">Paste Local -> Remote</button>
        <button id="copyRemote">Copy Remote -> Local</button>
      </div>
      <div id="clipStatus" class="status"></div>
    </div>
    <button id="settingsToggle" class="settings-handle" aria-label="Viewer settings">
      <span></span><span></span><span></span>
    </button>
  </div>
  <div id="screen"></div>
  <script src="/static/rfb.bundle.js"></script>
  <script>
    const wsProto = window.location.protocol === "https:" ? "wss" : "ws";
    const url = `${{wsProto}}://${{window.location.host}}/sessions/{name}/ws`;
    const rfb = new RFB(document.getElementById("screen"), url);
    rfb.scaleViewport = true;
    rfb.resizeSession = true;
    rfb.background = "rgb(5,11,20)";
    rfb.focusOnClick = true;
    rfb.viewOnly = false;

    const settingsDrawer = document.querySelector(".settings-drawer");
    const settingsToggle = document.getElementById("settingsToggle");
    const settingsPanel = document.getElementById("settingsPanel");
    settingsToggle.addEventListener("click", () => {{
      settingsPanel.classList.toggle("open");
      settingsDrawer.classList.toggle("open");
    }});

    const optScale = document.getElementById("optScale");
    const optResize = document.getElementById("optResize");
    const optViewOnly = document.getElementById("optViewOnly");
    optScale.addEventListener("change", () => {{ rfb.scaleViewport = optScale.checked; }});
    optResize.addEventListener("change", () => {{ rfb.resizeSession = optResize.checked; }});
    optViewOnly.addEventListener("change", () => {{ rfb.viewOnly = optViewOnly.checked; }});

    let remoteClipboardText = "";
    const clipStatus = document.getElementById("clipStatus");
    const setStatus = (msg) => {{
      clipStatus.textContent = msg;
      setTimeout(() => {{
        if (clipStatus.textContent === msg) clipStatus.textContent = "";
      }}, 2000);
    }};

    rfb.addEventListener("clipboard", (event) => {{
      remoteClipboardText = event?.detail?.text || "";
      if (remoteClipboardText) {{
        setStatus("Remote clipboard updated");
      }}
    }});

    document.getElementById("pasteLocal").addEventListener("click", async () => {{
      try {{
        const text = await navigator.clipboard.readText();
        rfb.clipboardPasteFrom(text);
        setStatus("Sent local clipboard");
      }} catch (err) {{
        setStatus("Clipboard read denied");
      }}
    }});

    document.getElementById("copyRemote").addEventListener("click", async () => {{
      try {{
        await navigator.clipboard.writeText(remoteClipboardText || "");
        setStatus("Copied remote clipboard");
      }} catch (err) {{
        setStatus("Clipboard write denied");
      }}
    }});
  </script>
</body>
</html>"""


async def viewer(request: web.Request) -> web.Response:
    username = request["auth_user"]
    name = request.match_info["name"]
    display = find_display_for_name(name, username)
    if display is None:
        raise web.HTTPNotFound(text="Session not found")
    return web.Response(text=render_viewer(name), content_type="text/html")


async def ws_proxy(request: web.Request) -> web.WebSocketResponse:
    username = request["auth_user"]
    name = request.match_info["name"]
    display = find_display_for_name(name, username)
    if display is None:
        raise web.HTTPNotFound(text="Unknown session")
    target_host = "127.0.0.1"
    target_port = 5900 + display

    ws = web.WebSocketResponse(heartbeat=30.0, max_msg_size=0)
    await ws.prepare(request)

    try:
        reader, writer = await asyncio.open_connection(target_host, target_port)
    except OSError as exc:
        await ws.close(message=f"Cannot connect to VNC backend: {exc}".encode("utf-8"))
        return ws

    async def tcp_to_ws() -> None:
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                await ws.send_bytes(data)
        finally:
            if not ws.closed:
                await ws.close()

    forward_task = asyncio.create_task(tcp_to_ws())
    try:
        async for msg in ws:
            if msg.type == WSMsgType.BINARY:
                writer.write(msg.data)
                await writer.drain()
            elif msg.type == WSMsgType.TEXT:
                # noVNC primarily sends binary; ignore text control frames.
                continue
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.ERROR):
                break
    finally:
        writer.close()
        await writer.wait_closed()
        forward_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await forward_task
    return ws


def build_ssl_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    if not os.path.exists(cert_path):
        raise FileNotFoundError(f"SSL cert not found: {cert_path}")
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"SSL key not found: {key_path}")

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return context


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TurboVNC HTTPS manager + noVNC websocket proxy")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=APP_PORT)
    parser.add_argument("--cert", default=os.environ.get("SSL_CERT_FILE", ""))
    parser.add_argument("--key", default=os.environ.get("SSL_KEY_FILE", ""))
    return parser.parse_args()


def ensure_runtime_prereqs() -> None:
    if os.geteuid() != 0:
        raise PermissionError("Run app.py as root (sudo) so local user password verification works.")
    if not TURBOVNC_BIN.exists():
        raise FileNotFoundError(f"TurboVNC binary not found at {TURBOVNC_BIN}")
    if not XSTARTUP_SCRIPT.exists():
        raise FileNotFoundError(f"xstartup script not found at {XSTARTUP_SCRIPT}")
    has_runuser = Path("/usr/sbin/runuser").exists()
    has_sudo = Path("/usr/bin/sudo").exists()
    if not has_runuser and not has_sudo:
        raise FileNotFoundError("Either runuser or sudo is required for per-user TurboVNC execution.")


def create_app() -> web.Application:
    app = web.Application(middlewares=[auth_middleware])
    app.add_routes(
        [
            web.get("/login", login_get),
            web.post("/login", login_post),
            web.get("/logout", logout),
            web.get("/", index),
            web.static("/static", str(Path(__file__).with_name("static"))),
            web.post("/sessions/create", create_session),
            web.post("/sessions/{name}/delete", delete_session),
            web.get("/sessions/{name}/view", viewer),
            web.get("/sessions/{name}/ws", ws_proxy),
        ]
    )
    return app


def main() -> None:
    args = parse_args()
    if args.port != APP_PORT:
        raise SystemExit(f"Only port {APP_PORT} is allowed.")
    if not args.cert or not args.key:
        raise SystemExit("You must provide user-generated SSL cert and key via --cert/--key or SSL_CERT_FILE/SSL_KEY_FILE.")

    ensure_runtime_prereqs()
    ssl_context = build_ssl_context(args.cert, args.key)
    app = create_app()
    web.run_app(app, host=args.host, port=args.port, ssl_context=ssl_context)


if __name__ == "__main__":
    main()
