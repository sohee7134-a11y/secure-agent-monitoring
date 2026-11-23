"""Anomaly rules for tool calls of a mail agent.

Each rule looks at one proposed tool call together with the session history and returns
zero or more Findings (rule id, risk cost, reason). Costs are charged to the session risk
budget. The rules target what the preventive layers (1-3) can miss:

  R1 TAINT      an argument (recipient, URL, file) appears in untrusted context but not in
                the user's own instruction -> the value was probably injected
  R2 NEW_EXT    recipient outside the user's domain and never contacted before
  R3 BULK       forward/export of many messages, or a mailbox-wide query
  R4 EXFIL_URL  outgoing text contains a URL with a long or encoded query (data in a URL)
  R5 BURST      many outgoing actions in a short window
  R6 OFF_PLAN   tool not in the plan that Layer 1 expected from the user's instruction
  R7 RETRY      the same kind of action is retried after being blocked or denied
  R8 UPSTREAM   other layers raised a warning (injection score, rule near-miss, user denial)
  R9 TICKET     the call is outside every Capability Ticket of the session (tool, target, uses, expiry)
  R10 PROBING   repeated out-of-ticket attempts in one session
"""
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlparse

OUTGOING = {"send_email", "forward_email", "reply_email", "http_get", "upload_file", "share_file"}

COST = {"R1": 35, "R2": 15, "R3": 40, "R4": 40, "R5": 20, "R6": 20, "R7": 30, "R8": 15,
        "R9": 60, "R10": 30}   # R9/R10 are computed in monitor.py from Capability Tickets

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URL = re.compile(r"https?://[^\s<>\"')\]]+")
_B64 = re.compile(r"^[A-Za-z0-9+/=_-]{24,}$")
_HEX = re.compile(r"^[0-9a-fA-F]{24,}$")


@dataclass
class Finding:
    rule: str
    cost: int
    reason: str


def _values(args):
    """All string values in the tool arguments (flattened)."""
    out = []
    for v in (args or {}).values():
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, (list, tuple)):
            out += [x for x in v if isinstance(x, str)]
    return out


def _recipients(args):
    r = []
    for k in ("to", "cc", "bcc", "recipient", "recipients"):
        v = (args or {}).get(k)
        if isinstance(v, str):
            r += _EMAIL.findall(v)
        elif isinstance(v, (list, tuple)):
            r += [x for s in v for x in _EMAIL.findall(str(s))]
    return [x.lower() for x in r]


def _suspicious_url(u):
    p = urlparse(u)
    q = parse_qsl(p.query, keep_blank_values=True)
    if len(p.query) > 120:
        return "query longer than 120 characters"
    for k, v in q:
        if _B64.match(v) or _HEX.match(v):
            return f"encoded value in parameter '{k}'"
    if any(len(seg) > 60 for seg in p.path.split("/")):
        return "long path segment"
    return None


def r1_taint(call, s):
    found = []
    instr = s.instruction_text.lower()
    for val in _recipients(call.args) + [u for v in _values(call.args) for u in _URL.findall(v)]:
        low = val.lower()
        if low in s.untrusted_text.lower() and low not in instr:
            found.append(Finding("R1", COST["R1"], f"'{val}' comes from untrusted context, not from the user"))
    return found


def r2_new_external(call, s):
    out = []
    for r in _recipients(call.args):
        dom = r.split("@")[-1]
        if dom not in s.trusted_domains and r not in s.contacts:
            out.append(Finding("R2", COST["R2"], f"first contact with external address {r}"))
    return out


def r3_bulk(call, s):
    n = len(call.args.get("message_ids", []) or [])
    q = str(call.args.get("query", "")).strip().lower()
    mailbox_wide = "query" in call.args and q in ("*", "all", "in:all", "")
    if call.tool == "export_mailbox" or (call.tool == "forward_email" and (n >= 5 or mailbox_wide)):
        return [Finding("R3", COST["R3"], f"bulk {call.tool} ({n or 'all'} messages)")]
    return []


def r4_exfil_url(call, s):
    out = []
    if call.tool not in OUTGOING:
        return out
    for v in _values(call.args):
        for u in _URL.findall(v):
            why = _suspicious_url(u)
            if why:
                out.append(Finding("R4", COST["R4"], f"possible data in URL ({why})"))
    return out


def r5_burst(call, s, window=60.0, limit=3):
    if call.tool not in OUTGOING:
        return []
    recent = [t for t in s.outgoing_times if call.ts - t <= window]
    if len(recent) >= limit:
        return [Finding("R5", COST["R5"], f"{len(recent) + 1} outgoing actions within {int(window)} s")]
    return []


def r6_off_plan(call, s):
    if s.expected_tools and call.tool not in s.expected_tools:
        return [Finding("R6", COST["R6"], f"tool '{call.tool}' not in expected plan {sorted(s.expected_tools)}")]
    return []


def r7_retry(call, s):
    if call.tool in s.blocked_tools:
        return [Finding("R7", COST["R7"], f"'{call.tool}' retried after a block or denial")]
    return []


def r8_upstream(call, s):
    out = []
    for layer, msg in (call.upstream or {}).items():
        if msg:
            out.append(Finding("R8", COST["R8"], f"{layer}: {msg}"))
    return out


RULES = [r1_taint, r2_new_external, r3_bulk, r4_exfil_url, r5_burst, r6_off_plan, r7_retry, r8_upstream]
