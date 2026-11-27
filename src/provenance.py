# THE verdict rule. A block requires CONTENT EVIDENCE bound to a protected path.
#
#   taint (PID read protected path)  -> provenance + search scope only
#   content evidence (>= min_contig) -> the actual forbidden bytes in the payload
#   BLOCK  <=>  content evidence present
#
# Never blocks on: taint alone, network access alone, destination/SNI, reputation.
# Enforcement is per-request / per-flow. There is no app-wide kill path here.

PLANE_GX = "gx-boundary"
PLANE_GX_BACKSTOP = "gx-proxy"
PLANE_PACKET = "packet-decrypt"

def allowed_sources(ledger_sources, scope, all_sources):
    if scope == "global":
        return set(all_sources)
    return set(ledger_sources or ())

def verdict(evidence, plane, armed=True, action="403", tainted=()):
    """evidence: dict from AnchorIndex.match / match_keys (+ optional names_hit)."""
    ev = evidence or {}
    hit = bool(ev.get("hit"))
    out = {
        "plane": plane,
        "verdict": "allow",
        "action": "none",
        "provenance": sorted(tainted or ()),
        "evidence": ev if hit else None,
        "reason": "",
        "scope": "per-flow",
    }
    if not hit:
        out["reason"] = ("no protected bytes in payload"
                         + (" (process is tainted, but taint alone is not a block reason)"
                            if tainted else ""))
        return out
    if not armed:
        out["verdict"] = "audit"
        out["reason"] = "content evidence present but protection disarmed (audit only)"
        return out
    out["verdict"] = "block"
    out["action"] = action if action in ("403", "kill") else "403"
    out["reason"] = ("payload carries %d contiguous bytes of %s"
                     % (ev.get("length", 0), ev.get("source_path") or ev.get("source_id", "")))
    return out

def name_evidence(names_hits):
    """Wrapped-name signal is corroborating evidence, never sufficient alone."""
    return {"corroborating": names_hits or []}
