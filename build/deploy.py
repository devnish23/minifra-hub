"""
Minifra Agent Deployment Script
Pushes minifra-agent.exe to all configured endpoints via WinRM,
then installs and starts it as a Windows Service.

Usage:  python build/deploy.py
        python build/deploy.py --remove    (uninstall from all endpoints)
"""
import argparse
import base64
import json
import os
import sys
import time

try:
    import winrm
except ImportError:
    print("[ERROR] pywinrm not installed. Run: pip install pywinrm")
    sys.exit(1)

CFG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "hub-config.json")
AGENT_EXE = os.path.join(os.path.dirname(__file__), "..", "dist", "minifra-agent.exe")
REMOTE_DIR = r"C:\Program Files\MinifraSecure"
REMOTE_EXE = rf"{REMOTE_DIR}\minifra-agent.exe"
REMOTE_CFG = rf"{REMOTE_DIR}\agent-config.json"


def load_config():
    with open(CFG_PATH) as f:
        return json.load(f)


def make_session(ep: dict):
    return winrm.Session(
        target=ep["ip"],
        auth=(ep["username"], ep["password"]),
        transport=ep.get("transport", "ntlm"),
        server_cert_validation="ignore",
        read_timeout_sec=60,
        operation_timeout_sec=55,
    )


def run_ps(session, script: str, label: str = "") -> bool:
    result = session.run_ps(script)
    if result.status_code != 0:
        stderr = result.std_err.decode("utf-8", errors="replace").strip()
        print(f"    [WARN] {label}: {stderr[:200]}")
        return False
    stdout = result.std_out.decode("utf-8", errors="replace").strip()
    if stdout:
        print(f"    {stdout[:200]}")
    return True


def upload_file(session, local_path: str, remote_path: str) -> bool:
    """Upload a binary file via WinRM by base64-encoding chunks."""
    print(f"    Uploading {os.path.basename(local_path)} ({os.path.getsize(local_path) / 1024 / 1024:.1f} MB) ...")
    with open(local_path, "rb") as f:
        data = f.read()

    b64 = base64.b64encode(data).decode("ascii")
    chunk_size = 50_000  # ~50KB per chunk (WinRM has payload limits)
    chunks = [b64[i:i+chunk_size] for i in range(0, len(b64), chunk_size)]

    # Start fresh
    run_ps(session, f'New-Item -ItemType Directory -Force -Path "{REMOTE_DIR}" | Out-Null', "mkdir")
    run_ps(session, f'Remove-Item -Force -Path "{remote_path}" -ErrorAction SilentlyContinue', "cleanup")

    for i, chunk in enumerate(chunks):
        script = f"""
$chunk = [System.Convert]::FromBase64String('{chunk}')
$stream = [System.IO.File]::Open('{remote_path}', [System.IO.FileMode]::Append)
$stream.Write($chunk, 0, $chunk.Length)
$stream.Close()
"""
        if not run_ps(session, script, f"chunk {i+1}/{len(chunks)}"):
            return False
        if (i + 1) % 10 == 0:
            print(f"    Progress: {(i+1)/len(chunks)*100:.0f}%")

    return True


def install_agent(ep: dict, cfg: dict, remove: bool = False):
    ip = ep["ip"]
    hostname = ep.get("hostname", ip)
    print(f"\n{'─'*56}")
    print(f"  {'Removing' if remove else 'Installing'} on {hostname} ({ip})")
    print(f"{'─'*56}")

    try:
        session = make_session(ep)

        # Test connectivity
        result = session.run_ps("echo OK")
        if result.status_code != 0 or b"OK" not in result.std_out:
            print(f"  [ERROR] Cannot connect to {ip} via WinRM")
            return False
        print(f"  ✓ WinRM connection OK")

        if remove:
            run_ps(session, f'Stop-Service MinifraAgent -ErrorAction SilentlyContinue', "stop service")
            run_ps(session, f'& "{REMOTE_EXE}" remove', "remove service")
            run_ps(session, f'Remove-Item -Recurse -Force "{REMOTE_DIR}" -ErrorAction SilentlyContinue', "cleanup")
            print(f"  ✓ Agent removed from {hostname}")
            return True

        # Upload agent.exe
        if not upload_file(session, AGENT_EXE, REMOTE_EXE):
            print(f"  [ERROR] Upload failed for {ip}")
            return False
        print(f"  ✓ Agent uploaded")

        # Write agent-config.json
        agent_cfg = {
            "hub_url": f"http://{cfg.get('hub_ip', '192.168.1.109')}:{cfg.get('port', 8080)}",
            "auth_token": cfg["auth_token"],
            "agent_id": f"agent-{hostname.lower().replace(' ', '-')}",
            "report_interval_s": cfg.get("collect_interval_s", 30),
            "department": ep.get("department", "Endpoint"),
            "role": ep.get("role", "Monitored User"),
        }
        cfg_json = json.dumps(agent_cfg, indent=2).replace('"', '\\"')
        run_ps(session, f'Set-Content -Path "{REMOTE_CFG}" -Value "{cfg_json}"', "write config")
        print(f"  ✓ Agent config written")

        # Install as Windows Service
        run_ps(session, f'& "{REMOTE_EXE}" stop    2>$null', "stop existing")
        run_ps(session, f'& "{REMOTE_EXE}" remove  2>$null', "remove existing")
        run_ps(session, f'& "{REMOTE_EXE}" install', "install service")
        run_ps(session, f'& "{REMOTE_EXE}" start',  "start service")
        print(f"  ✓ MinifraAgent service installed and started")

        # Verify it's running
        time.sleep(2)
        result = session.run_ps('(Get-Service MinifraAgent -ErrorAction SilentlyContinue).Status')
        status_txt = result.std_out.decode().strip()
        print(f"  ✓ Service status: {status_txt or 'unknown'}")

        return True

    except Exception as exc:
        print(f"  [ERROR] {ip}: {exc}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Deploy Minifra Agent to endpoints")
    parser.add_argument("--remove", action="store_true", help="Uninstall agent from all endpoints")
    args = parser.parse_args()

    if not os.path.exists(CFG_PATH):
        print(f"[ERROR] Config not found: {CFG_PATH}")
        sys.exit(1)

    if not args.remove and not os.path.exists(AGENT_EXE):
        print(f"[ERROR] Agent EXE not found: {AGENT_EXE}")
        print("        Run build.bat first to compile minifra-agent.exe")
        sys.exit(1)

    cfg = load_config()
    endpoints = cfg.get("endpoints", [])
    if not endpoints:
        print("[ERROR] No endpoints in config/hub-config.json")
        sys.exit(1)

    print(f"\n  Minifra Agent {'Removal' if args.remove else 'Deployment'}")
    print(f"  Target: {len(endpoints)} endpoint(s)\n")

    results = []
    for ep in endpoints:
        ok = install_agent(ep, cfg, remove=args.remove)
        results.append((ep.get("hostname", ep["ip"]), ok))

    print(f"\n{'═'*56}")
    print("  SUMMARY")
    print(f"{'═'*56}")
    for hostname, ok in results:
        status = "✓  SUCCESS" if ok else "✗  FAILED "
        print(f"  {status}  {hostname}")
    success = sum(1 for _, ok in results if ok)
    print(f"\n  {success}/{len(results)} endpoints completed successfully")

    if success == len(results) and not args.remove:
        print("\n  Agents are now running as Windows Services.")
        print("  Open Minifra Secure Console → Config → Hub tab")
        print(f"  Set Hub URL to: https://192.168.1.109:8080")
        print(f"  Set Auth Token to: {cfg['auth_token']}")


if __name__ == "__main__":
    main()
