"""Layer 4 runtime monitor: session risk budget + audit log + anomaly rules.

Gateway integration (three calls):

    mon = Monitor("audit.jsonl")
    mon.start_session(sid, user="alice@corp.example", instruction="Reply to Bob ...",
                      expected_tools={"read_email", "reply_email"})      # from Layer 1
    mon.observe_context(sid, source="email:123", text=email_body)       # untrusted data
    d = mon.check(sid, ToolCall("send_email", {"to": ..., "body": ...},
                                upstream={"layer1": None, "layer2": None}))
    # d.action in {"allow", "confirm", "block"}; "confirm" -> Layer 3 asks the user
    mon.record_outcome(sid, d.call_id, executed=True, user_confirmed=None)

Decision rule (per session, budget B = 100 by default):
    the call's findings cost c; used' = used + c
    block   if used' >= B, or a single call costs >= HARD (default 60)
    confirm if c > 0 and used' >= B * CONFIRM_AT (default 0.3)
    allow   otherwise
A blocked session stays halted until a human resets it.
"""
import itertools
import time
from dataclasses import dataclass, field

from .audit import AuditLog, redact
from .rules import COST, OUTGOING, RULES, Finding, _recipients
from .tickets import Ticket


@dataclass
class ToolCall:
    tool: str
    args: dict
    upstream: dict = field(default_factory=dict)   # warnings from layers 1-3 (None = no warning)
    ts: float = field(default_factory=time.time)
    ticket_id: str = None                          # Capability Ticket the gateway used for this call


@dataclass
class Decision:
    action: str
    call_id: int
    cost: int
    used: int
    budget: int
    reasons: list
    revoke: list = field(default_factory=list)     # ticket ids the gateway should revoke now


@dataclass
class Session:
    sid: str
    user: str
    instruction_text: str
    expected_tools: set
    trusted_domains: set
    contacts: set
    budget: int
    used: int = 0
    halted: bool = False
    untrusted_text: str = ""
    outgoing_times: list = field(default_factory=list)
    blocked_tools: set = field(default_factory=set)
    tickets: dict = field(default_factory=dict)
    ticket_violations: int = 0


class Monitor:
    def __init__(self, log_path, budget=100, confirm_at=0.3, hard=60):
        self.log = AuditLog(log_path)
        self.budget, self.confirm_at, self.hard = budget, confirm_at, hard
        self.sessions = {}
        self._ids = itertools.count(1)

    # ------------------------------------------------------------------ session lifecycle
    def start_session(self, sid, user, instruction, expected_tools=(), contacts=(), trusted_domains=None):
        dom = user.split("@")[-1].lower()
        s = Session(sid, user, instruction, set(expected_tools),
                    set(trusted_domains or {dom}), {c.lower() for c in contacts}, self.budget)
        self.sessions[sid] = s
        self.log.append("session_start", sid, user=user, instruction=redact(instruction, keep=60),
                        expected_tools=sorted(s.expected_tools), budget=self.budget)
        return s

    def on_ticket_issued(self, sid, ticket):
        """Register a Capability Ticket issued by the policy engine for this session."""
        s = self.sessions[sid]
        t = ticket if isinstance(ticket, Ticket) else Ticket.from_any(ticket)
        s.tickets[t.ticket_id] = t
        s.expected_tools |= t.tools                   # granted tools count as planned (R6)
        self.log.append("ticket_issued", sid, ticket_id=t.ticket_id, tools=sorted(t.tools),
                        targets=sorted(t.targets), max_uses=t.max_uses, expires_at=t.expires_at)
        return t

    def observe_context(self, sid, source, text):
        """Register untrusted context (email body, attachment, web page) the agent has read."""
        s = self.sessions[sid]
        s.untrusted_text += "\n" + (text or "")
        self.log.append("context", sid, source=source, content=redact(text))

    # ------------------------------------------------------------------ the check
    def check(self, sid, call):
        s = self.sessions[sid]
        cid = next(self._ids)
        if s.halted:
            d = Decision("block", cid, 0, min(s.used, s.budget), s.budget, ["session halted after budget exhaustion"])
            self._log_decision(s, call, d)
            return d
        findings = [f for rule in RULES for f in rule(call, s)]
        findings += self._ticket_findings(s, call)
        cost = sum(f.cost for f in findings)
        s.used += cost
        if s.used >= s.budget or cost >= self.hard:
            action = "block"
            if s.used >= s.budget:
                s.halted = True
        elif cost > 0 and s.used >= s.budget * self.confirm_at:
            action = "confirm"
        else:
            action = "allow"
        if action == "block":
            s.blocked_tools.add(call.tool)
        revoke = []
        if s.halted:                                   # budget exhausted: withdraw every live ticket
            for t in s.tickets.values():
                if not t.revoked:
                    t.revoked = True; revoke.append(t.ticket_id)
        d = Decision(action, cid, cost, min(s.used, s.budget), s.budget,
                     [f"{f.rule}(+{f.cost}) {f.reason}" for f in findings], revoke)
        self._log_decision(s, call, d)
        if revoke:
            self.log.append("ticket_revoked", s.sid, tickets=revoke, reason="risk budget exhausted")
        return d

    def _ticket_findings(self, s, call):
        if not s.tickets:
            return []
        t = s.tickets.get(call.ticket_id) if call.ticket_id else None
        if t is None:
            # no ticket named: does any live ticket cover the call?
            ok = [x for x in s.tickets.values() if x.violation(call.tool, _recipients(call.args), call.ts) is None]
            why = None if ok else f"no ticket covers '{call.tool}'"
        else:
            why = t.violation(call.tool, _recipients(call.args), call.ts)
        if not why:
            return []
        s.ticket_violations += 1
        out = [Finding("R9", COST["R9"], why)]
        if s.ticket_violations >= 2:
            out.append(Finding("R10", COST["R10"], f"{s.ticket_violations} out-of-ticket attempts (probing)"))
        return out

    def record_outcome(self, sid, call_id, executed, user_confirmed=None, call=None):
        """Called after execution or after the Layer 3 confirmation dialog."""
        s = self.sessions[sid]
        if user_confirmed is False and call is not None:
            s.blocked_tools.add(call.tool)               # a denial counts for R7 (retries)
        if executed and call is not None:
            if call.ticket_id in s.tickets:
                s.tickets[call.ticket_id].used += 1
            if call.tool in OUTGOING:
                s.outgoing_times.append(call.ts)
            s.contacts |= set(_recipients(call.args))
        self.log.append("outcome", sid, call_id=call_id, executed=executed, user_confirmed=user_confirmed)

    def reset(self, sid, by):
        s = self.sessions[sid]
        s.used, s.halted = 0, False
        self.log.append("reset", sid, by=by)

    # ------------------------------------------------------------------ logging
    def _log_decision(self, s, call, d):
        args = {k: (redact(v) if k in ("body", "text", "content") and isinstance(v, str) else v)
                for k, v in call.args.items()}
        self.log.append("tool_call", s.sid, call_id=d.call_id, tool=call.tool, args=args, ticket=call.ticket_id,
                        upstream={k: v for k, v in (call.upstream or {}).items() if v},
                        decision=d.action, cost=d.cost, used=d.used, budget=d.budget, reasons=d.reasons)
