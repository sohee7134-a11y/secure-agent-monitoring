"""Render an audit log as a static HTML page (timeline per session, decision colors, risk bars).

    python3 -m monitor.report demo/out/audit.jsonl demo/out/report.html
"""
import html
import sys
from collections import defaultdict

from .audit import AuditLog

COLOR = {"allow": "#2e7d32", "confirm": "#ef6c00", "block": "#c62828"}


def render(log_path, out_path):
    log = AuditLog(log_path)
    ok, n = log.verify()
    sess, starts = defaultdict(list), {}
    for r in log.records():
        if r["kind"] == "session_start":
            starts[r["session"]] = r
        elif r["kind"] == "tool_call":
            sess[r["session"]].append(r)
    counts = defaultdict(int)
    for calls in sess.values():
        for c in calls:
            counts[c["decision"]] += 1
    e = html.escape
    parts = [f"""<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>Audit Monitor</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{{font-family:system-ui,sans-serif;margin:24px;max-width:1000px;background:#fafafa;color:#222}}
.card{{background:#fff;border:1px solid #ddd;border-radius:8px;padding:12px 16px;margin:12px 0}}
.tag{{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:12px;font-weight:600}}
.bar{{height:8px;background:#eee;border-radius:4px;width:160px;display:inline-block;vertical-align:middle}}
.bar i{{display:block;height:8px;border-radius:4px}}
td{{padding:3px 8px;vertical-align:top;font-size:14px}} .r{{color:#555;font-size:12px}}
.kpi span{{display:inline-block;margin-right:24px;font-size:15px}}
</style></head><body><h1>Layer 4 — Audit &amp; Monitoring</h1>
<div class="card kpi"><span>chain: <b style="color:{'#2e7d32' if ok else '#c62828'}">{'intact' if ok else f'BROKEN at record {n}'}</b>
({n if ok else '?'} records)</span>""" + "".join(
        f'<span><span class="tag" style="background:{COLOR[k]}">{k}</span> {counts[k]}</span>' for k in ("allow", "confirm", "block"))
        + "</div>"]
    for sid, calls in sess.items():
        st = starts.get(sid, {})
        instr = (st.get("instruction") or {}).get("preview", "")
        parts.append(f'<div class="card"><b>{e(sid)}</b> — <i>{e(instr)}</i><table>')
        for c in calls:
            pct = int(100 * c["used"] / c["budget"])
            col = COLOR[c["decision"]]
            reasons = "<br>".join(e(x) for x in c["reasons"])
            parts.append(f'<tr><td>#{c["call_id"]}</td><td><code>{e(c["tool"])}</code></td>'
                         f'<td><span class="tag" style="background:{col}">{c["decision"]}</span></td>'
                         f'<td><span class="bar"><i style="width:{pct}%;background:{col}"></i></span> {c["used"]}/{c["budget"]}</td>'
                         f'<td class="r">{reasons}</td></tr>')
        parts.append("</table></div>")
    parts.append("</body></html>")
    open(out_path, "w", encoding="utf-8").write("\n".join(parts))
    return out_path


if __name__ == "__main__":
    print(render(sys.argv[1], sys.argv[2]))
