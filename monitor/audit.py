"""Tamper-evident audit log (Layer 4: Logging & Monitoring).

Every gateway event is appended as one JSON line. Each record stores the SHA-256 of the
previous record, so deleting, reordering or editing any line breaks the chain and
`verify()` reports the first broken position.

Privacy: message bodies and other free text are never written in clear. Only a digest
and a length are kept (`redact`), so the log can prove *what* was seen without holding
user data.
"""
import hashlib
import json
import os
import time

GENESIS = "0" * 64


def _canon(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def redact(text, keep=0):
    """Replace free text by its digest and length (optionally keep a short prefix)."""
    if text is None:
        return None
    out = {"sha256": sha256(text)[:16], "len": len(text)}
    if keep:
        out["preview"] = text[:keep]
    return out


class AuditLog:
    def __init__(self, path):
        self.path = path
        self.prev = GENESIS
        self.seq = 0
        if os.path.exists(path):                       # continue an existing chain
            for rec in self.records():
                self.prev, self.seq = rec["hash"], rec["seq"] + 1

    def append(self, kind, session, **fields):
        rec = {"seq": self.seq, "ts": round(time.time(), 3), "kind": kind,
               "session": session, "prev": self.prev, **fields}
        rec["hash"] = sha256(_canon(rec))
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(_canon(rec) + "\n")
        self.prev, self.seq = rec["hash"], self.seq + 1
        return rec

    def records(self):
        if not os.path.exists(self.path):
            return
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)

    def verify(self):
        """Return (True, n) if the chain is intact, else (False, first bad seq)."""
        prev, n = GENESIS, 0
        for i, rec in enumerate(self.records()):
            h = rec.pop("hash")
            if rec.get("prev") != prev or rec.get("seq") != i or sha256(_canon(rec)) != h:
                return False, i
            prev, n = h, i + 1
        return True, n
