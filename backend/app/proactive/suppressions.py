"""Suppression matching (Phase 2 Task 3).

A suppression applies to a finding when:
  suppression.rule_id == finding rule_id (or "*" wildcard), AND
  every specified scope dimension matches (unspecified = wildcard).

Scope dimensions:
  hosts: exact IP/hostname match (either endpoint of the five_tuple)
  cidrs: finding endpoint IP inside any listed CIDR
  domains: wildcard match (*.legacy.example) against SNI/host evidence
  ports: either endpoint port equals a listed port
"""
from __future__ import annotations

import fnmatch
import ipaddress
from datetime import datetime, timezone


def _finding_hosts(finding: dict) -> list[str]:
    hosts: list[str] = []
    for k in ("server", "host", "dst_ip", "src_ip", "sni"):
        v = finding.get(k)
        if v:
            hosts.append(str(v))
    ft = str(finding.get("five_tuple", "") or "")
    if "-" in ft and ":" in ft:
        try:
            left, right = ft.split("-", 1)
            for part in (left, right):
                hosts.append(part.rsplit(":", 1)[0])
        except Exception:
            pass
    return hosts


def _finding_ports(finding: dict) -> list[int]:
    ports: list[int] = []
    for k in ("server_port", "src_port", "dst_port", "port"):
        try:
            if finding.get(k) is not None:
                ports.append(int(finding[k]))
        except Exception:
            pass
    ft = str(finding.get("five_tuple", "") or "")
    if "-" in ft and ":" in ft:
        try:
            for part in ft.split("-", 1):
                ports.append(int(part.rsplit(":", 1)[1]))
        except Exception:
            pass
    return ports


def _finding_domains(finding: dict) -> list[str]:
    doms: list[str] = []
    for k in ("sni", "server", "host", "domain"):
        v = finding.get(k)
        if v and "." in str(v):
            doms.append(str(v).lower())
    ev = finding.get("evidence") or {}
    if isinstance(ev, dict):
        for k in ("sni", "hostname", "domain", "cn"):
            v = ev.get(k)
            if v and "." in str(v):
                doms.append(str(v).lower())
    return doms


def scope_matches(scope: dict, finding: dict) -> bool:
    """True when every specified dimension matches (AND of dimensions)."""
    scope = scope or {}
    hosts = [h.lower() for h in (scope.get("hosts") or [])]
    if hosts:
        fh = [h.lower() for h in _finding_hosts(finding)]
        if not any(h in fh for h in hosts):
            return False
    cidrs = scope.get("cidrs") or []
    if cidrs:
        fh = _finding_hosts(finding)
        hit = False
        for c in cidrs:
            try:
                net = ipaddress.ip_network(c, strict=False)
                for h in fh:
                    try:
                        if ipaddress.ip_address(h) in net:
                            hit = True
                            break
                    except ValueError:
                        continue
                if hit:
                    break
            except ValueError:
                continue
        if not hit:
            return False
    domains = [d.lower() for d in (scope.get("domains") or [])]
    if domains:
        fd = _finding_domains(finding)
        if not any(fnmatch.fnmatch(d, pat) for d in fd for pat in domains):
            return False
    ports = scope.get("ports") or []
    if ports:
        try:
            wanted = {int(p) for p in ports}
        except Exception:
            wanted = set()
        if not (wanted & set(_finding_ports(finding))):
            return False
    return True


def is_active(status: str, expires_at) -> bool:
    if status != "approved":
        return False
    try:
        now = datetime.now(timezone.utc)
        exp = expires_at
        if getattr(exp, "tzinfo", None) is None and exp is not None:
            exp = exp.replace(tzinfo=timezone.utc)
        return bool(exp and exp > now)
    except Exception:
        return False


def match_suppression(rule_id: str, finding: dict, suppressions) -> object | None:
    """Return the first active suppression matching (rule_id, finding)."""
    for s in suppressions or []:
        if getattr(s, "rule_id", "") not in (rule_id, "*"):
            continue
        if not is_active(getattr(s, "status", ""), getattr(s, "expires_at", None)):
            continue
        try:
            scope = getattr(s, "scope", {}) or {}
        except Exception:
            scope = {}
        if scope_matches(scope, finding):
            return s
    return None


def filter_active(rows, now=None) -> list:
    now = now or datetime.now(timezone.utc)
    out = []
    for s in rows or []:
        exp = getattr(s, "expires_at", None)
        if getattr(s, "status", "") != "approved":
            continue
        try:
            if exp is not None and getattr(exp, "tzinfo", None) is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp and exp > now:
                out.append(s)
        except Exception:
            continue
    return out
