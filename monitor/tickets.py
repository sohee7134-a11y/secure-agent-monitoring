"""Capability Ticket view used by the monitor.

The gateway (planner + policy engine) issues tickets and enforces them. The monitor only needs
a read-only view to (1) log issuance and use, (2) count out-of-scope attempts, and (3) ask the
gateway to revoke a session's tickets when its risk budget is exhausted.

`Ticket.from_any` accepts a dict or an object with similar attribute names, so the team's own
ticket class can be passed without changes; adjust FIELD_ALIASES if its names differ.
"""
import time
from dataclasses import dataclass, field

FIELD_ALIASES = {
    "ticket_id": ("ticket_id", "id", "tid"),
    "tools": ("tools", "allowed_tools", "capabilities", "actions"),
    "targets": ("targets", "allowed_targets", "recipients", "resources", "scope"),
    "max_uses": ("max_uses", "uses", "limit", "quota"),
    "expires_at": ("expires_at", "expiry", "exp", "ttl_until"),
}


@dataclass
class Ticket:
    ticket_id: str
    tools: set
    targets: set = field(default_factory=set)        # empty = no target restriction
    max_uses: int = 0                                 # 0 = unlimited
    expires_at: float = 0.0                           # 0 = no expiry
    used: int = 0
    revoked: bool = False

    @classmethod
    def from_any(cls, t):
        get = (lambda k: t.get(k)) if isinstance(t, dict) else (lambda k: getattr(t, k, None))
        val = {}
        for name, keys in FIELD_ALIASES.items():
            val[name] = next((get(k) for k in keys if get(k) is not None), None)
        return cls(str(val["ticket_id"]), set(val["tools"] or []), {str(x).lower() for x in (val["targets"] or [])},
                   int(val["max_uses"] or 0), float(val["expires_at"] or 0))

    def violation(self, tool, targets, now=None):
        """Reason string if the call is outside this ticket, else None."""
        now = now or time.time()
        if self.revoked:
            return f"ticket {self.ticket_id} was revoked"
        if self.expires_at and now > self.expires_at:
            return f"ticket {self.ticket_id} expired"
        if self.max_uses and self.used >= self.max_uses:
            return f"ticket {self.ticket_id} used up ({self.used}/{self.max_uses})"
        if tool not in self.tools:
            return f"tool '{tool}' not granted by ticket {self.ticket_id} {sorted(self.tools)}"
        extra = [x for x in targets if self.targets and x not in self.targets]
        if extra:
            return f"target {extra} outside ticket {self.ticket_id} {sorted(self.targets)}"
        return None
