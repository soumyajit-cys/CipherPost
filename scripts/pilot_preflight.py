"""Pilot preflight checks (Task 5): run BEFORE installing CipherPost.

Local-only: every check runs on the pilot host and nothing is sent
anywhere. Output is one PASS/WARN/FAIL line per check plus a summary.
Exit codes: 0 = no FAIL, 1 = at least one FAIL, 2 = usage error.

Checks: OS/arch, container runtime or Kubernetes access, ports, disk,
clock sync, capture permissions (NET_RAW), DNS resolution, and network
path to the capture point. --post-install additionally checks the local
API health endpoint.

Every check function takes its I/O through injectable helpers
(run/connect/resolve) so tests can simulate failures deterministically.
"""
from __future__ import annotations

import argparse
import os
import platform
import shutil
import socket
import subprocess
import sys

MIN_DISK_GB = 5.0
DEFAULT_PORTS = (8000, 3000, 5432, 6379)


# --- injectable I/O -----------------------------------------------------------

def _run(cmd: list[str]) -> tuple[int, str]:
    """Run a command; returns (rc, combined output). Injectable in tests."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)


def _connect(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _resolve(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except OSError:
        return False


def _net_raw_available() -> tuple[bool, str]:
    """Try to open an AF_PACKET raw socket (needs CAP_NET_RAW)."""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.close()
        return True, ""
    except (OSError, AttributeError) as e:
        return False, str(e)


def _free_gb(path: str) -> float | None:
    try:
        st = os.statvfs(path)
        return (st.f_bavail * st.f_frsize) / (1024 ** 3)
    except OSError:
        return None


# --- checks (each returns (status, detail); status in PASS/WARN/FAIL) ----------

def check_os_arch() -> tuple[str, str]:
    machine = platform.machine()
    system = platform.system()
    if system == "Linux" and machine in ("x86_64", "aarch64"):
        return "PASS", f"{system} {machine} ({platform.release()})"
    return "WARN", (f"{system} {machine}: documented install paths target "
                    f"Linux x86_64/aarch64; continue only if you can run docker/k8s")


def check_container_runtime(run=None) -> tuple[str, str]:
    run = run or _run
    docker = shutil.which("docker")
    if not docker:
        return "FAIL", "docker not found (compose install path requires it)"
    rc, out = run(["docker", "info", "--format", "{{.ServerVersion}}"])
    if rc == 0:
        return "PASS", f"docker daemon reachable (server {out.strip().splitlines()[-1][:20]})"
    return "FAIL", f"docker installed but daemon unreachable: {out.strip()[:120]}"


def check_kubernetes(run=None) -> tuple[str, str]:
    run = run or _run
    kubectl = shutil.which("kubectl")
    if not kubectl:
        return "WARN", "kubectl not found (only needed for the Helm path)"
    rc, out = run(["kubectl", "version", "--short", "--request-timeout=5s"])
    if rc == 0:
        return "PASS", "kubectl talks to a cluster"
    return "WARN", f"kubectl present but no cluster access: {out.strip()[:100]}"


def check_ports(ports, connect=None) -> tuple[str, str]:
    connect = connect or _connect
    busy = [str(p) for p in ports if connect("127.0.0.1", p, 0.5)]
    if busy:
        return "WARN", (f"ports already in use on 127.0.0.1: {', '.join(busy)} — "
                        f"move the existing service or remap (publish a different host port)")
    return "PASS", f"free on 127.0.0.1: {', '.join(str(p) for p in ports)}"


def check_disk(path: str, free_gb=None, minimum: float = MIN_DISK_GB) -> tuple[str, str]:
    free_gb = free_gb or _free_gb
    free = free_gb(path)
    if free is None:
        return "FAIL", f"cannot stat {path}"
    if free < minimum:
        return "FAIL", f"{free:.1f} GB free at {path}, need >= {minimum} GB"
    if free < minimum * 2:
        return "WARN", f"only {free:.1f} GB free at {path} — plan capture/DB growth"
    return "PASS", f"{free:.1f} GB free at {path}"


def check_clock(run=None) -> tuple[str, str]:
    run = run or _run
    # chronyc tracking: "System time : 0.0000001 seconds fast of NTP time"
    rc, out = run(["chronyc", "tracking"])
    if rc == 0 and "System time" in out:
        line = [l for l in out.splitlines() if "System time" in l][0]
        return "PASS", line.strip()
    rc, out = run(["timedatectl", "show", "--property=NTPSynchronized"])
    if rc == 0 and "yes" in out.lower():
        return "PASS", "timedatectl: NTP synchronized"
    return "WARN", ("could not confirm clock sync (chrony/timedatectl). Clock drift "
                    "breaks certificate validity checks — configure NTP before install")


def check_capture_permissions(netraw=None) -> tuple[str, str]:
    netraw = netraw or _net_raw_available
    ok, detail = netraw()
    if ok:
        return "PASS", "CAP_NET_RAW: AF_PACKET socket opened"
    return "WARN", (f"cannot open a raw capture socket ({detail[:80]}). Needed only "
                    f"for live capture (docker grants it via cap_add); the API/replay "
                    f"path works without it")


def check_dns(hosts, resolve=None) -> tuple[str, str]:
    resolve = resolve or _resolve
    failed = [h for h in hosts if not resolve(h)]
    if failed:
        return "FAIL", f"DNS resolution failed for: {', '.join(failed)}"
    return "PASS", f"resolved: {', '.join(hosts)}"


def check_capture_path(target: str, connect=None) -> tuple[str, str]:
    """target is host:port of the capture point (e.g. the API or sensor)."""
    connect = connect or _connect
    host, _, port = target.rpartition(":")
    if not host or not port.isdigit():
        return "FAIL", f"capture-path target must be host:port, got {target!r}"
    if connect(host, int(port)):
        return "PASS", f"{host}:{port} reachable"
    return "FAIL", f"{host}:{port} not reachable from this host"


def check_post_install(base_url: str, fetch=None) -> tuple[str, str]:
    fetch = fetch or (lambda url: (_ for _ in ()).throw(OSError("no fetcher")))
    try:
        body = fetch(f"{base_url.rstrip('/')}/api/v1/health")
        if body.get("status") in ("ok", "degraded"):
            return "PASS", f"API health: {body.get('status')}"
        return "FAIL", f"API health reports: {body.get('status')}"
    except Exception as e:
        return "FAIL", f"API not reachable at {base_url}: {str(e)[:100]}"


# --- driver -------------------------------------------------------------------

def run_checks(ports=DEFAULT_PORTS, dns_hosts=("localhost",),
               capture_target=None, disk_path=".", post_install_url=None,
               run=None, connect=None, resolve=None, netraw=None,
               free_gb=None, fetch=None) -> list[tuple[str, str, str]]:
    results = []

    def add(name, fn, *a, **kw):
        try:
            status, detail = fn(*a, **kw)
        except Exception as e:  # a check must never abort the preflight
            status, detail = "WARN", f"check errored: {str(e)[:100]}"
        results.append((name, status, detail))

    add("os/arch", check_os_arch)
    add("container-runtime", check_container_runtime, run)
    add("kubernetes", check_kubernetes, run)
    add("ports", check_ports, tuple(ports), connect)
    add("disk", check_disk, disk_path, free_gb)
    add("clock-sync", check_clock, run)
    add("capture-permissions", check_capture_permissions, netraw)
    if dns_hosts:
        add("dns", check_dns, tuple(dns_hosts), resolve)
    if capture_target:
        add("capture-path", check_capture_path, capture_target, connect)
    if post_install_url:
        add("post-install-api", check_post_install, post_install_url, fetch)
    return results


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Pre-install checks for a CipherPost pilot host (local-only)")
    ap.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)),
                    help="comma-separated ports that must be free")
    ap.add_argument("--dns-hosts", default="localhost",
                    help="comma-separated hostnames to resolve")
    ap.add_argument("--capture-target", default=None,
                    help="host:port of the capture point / API to test")
    ap.add_argument("--disk-path", default=".", help="path whose filesystem must have room")
    ap.add_argument("--post-install", action="store_true",
                    help="also check http://127.0.0.1:8000/api/v1/health")
    ap.add_argument("--api-url", default="http://127.0.0.1:8000")
    args = ap.parse_args(argv)

    ports = tuple(int(p) for p in args.ports.split(",") if p.strip())
    dns_hosts = tuple(h for h in args.dns_hosts.split(",") if h.strip())
    results = run_checks(ports=ports, dns_hosts=dns_hosts,
                         capture_target=args.capture_target,
                         disk_path=args.disk_path,
                         post_install_url=args.api_url if args.post_install else None)

    print("CipherPost pilot preflight (local-only; nothing is sent anywhere)\n")
    n_fail = 0
    for name, status, detail in results:
        print(f"[{status:4}] {name:20} {detail}")
        if status == "FAIL":
            n_fail += 1
    print(f"\n{n_fail} FAIL, "
          f"{sum(1 for _, s, _ in results if s == 'WARN')} WARN, "
          f"{sum(1 for _, s, _ in results if s == 'PASS')} PASS")
    print("All FAIL items must be resolved before install; WARN items need a decision.")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
