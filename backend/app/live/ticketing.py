"""
Ticketing integration (track 4): pluggable backends behind one interface,
mirroring the AlertAdapter pattern. Auto-creates tickets for findings at or
above TICKET_MIN_SEVERITY so remediation has a tracked workflow.

Currently ships Jira Cloud/Server (REST v3/v2-compatible create-issue).
ServiceNow/custom systems implement TicketBackend.create().
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod

import httpx

from app.core.config import settings

log = logging.getLogger("cipherpost.live.ticketing")

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class TicketBackend(ABC):
    name: str = "base"

    @abstractmethod
    def create(self, alert: dict) -> str | None:
        """Create a ticket; return the ticket key/URL, or None on failure."""


class JiraBackend(TicketBackend):
    name = "jira"

    def __init__(self, url: str, email: str, api_token: str,
                 project: str, issue_type: str = "Task", timeout: float = 8):
        self.url = url.rstrip("/")
        self.email = email
        self.api_token = api_token
        self.project = project
        self.issue_type = issue_type
        self.timeout = timeout

    def create(self, alert: dict) -> str | None:
        summary = f"[CipherPost/{alert.get('severity', 'info')}] {alert.get('title', 'finding')}"
        body = (
            f"*Five-tuple:* {alert.get('five_tuple', '')}\n"
            f"*Protocol:* {alert.get('protocol', '')}\n"
            f"*Rule:* {alert.get('rule_id', '')}\n"
            f"*Risk score:* {alert.get('risk_score')}\n\n"
            f"{alert.get('description', '')}"
        )
        payload = {"fields": {
            "project": {"key": self.project},
            "summary": summary[:255],
            "description": body,
            "issuetype": {"name": self.issue_type},
            "labels": ["cipherpost", f"severity-{alert.get('severity', 'info')}"],
        }}
        try:
            r = httpx.post(f"{self.url}/rest/api/3/issue", json=payload,
                           auth=(self.email, self.api_token), timeout=self.timeout)
            if r.status_code in (200, 201):
                key = r.json().get("key", "")
                return f"{self.url}/browse/{key}" if key else key
            log.warning("jira create failed: %s %s", r.status_code, r.text[:200])
            return None
        except Exception as e:
            log.warning("jira create error: %s", e)
            return None


def load_ticket_backend() -> TicketBackend | None:
    """Build the configured backend, or None when ticketing is disabled."""
    if not settings.TICKETING_ENABLED:
        return None
    if settings.JIRA_URL and settings.JIRA_PROJECT:
        return JiraBackend(settings.JIRA_URL, settings.JIRA_EMAIL,
                           settings.JIRA_API_TOKEN, settings.JIRA_PROJECT,
                           settings.JIRA_ISSUE_TYPE)
    log.warning("ticketing enabled but no backend configured (need JIRA_URL + JIRA_PROJECT)")
    return None


def should_ticket(alert: dict) -> bool:
    sev = (alert.get("severity") or "info").lower()
    floor = (settings.TICKET_MIN_SEVERITY or "critical").lower()
    return SEV_ORDER.get(sev, 0) >= SEV_ORDER.get(floor, 4)
