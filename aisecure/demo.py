"""Synthetic replay data. Not GSS logs or a reconstruction of the real incident."""
from datetime import timedelta
from .schema import utcnow, iso


def sample(now=None) -> dict:
    now = (now or utcnow()).replace(microsecond=0)
    start = now - timedelta(minutes=12)
    def asset(aid, kind, exposed, privilege, sensitive, patch, vulnerability=None):
        return {"id": aid, "kind": kind, "internet_exposed": exposed, "privileged_path": privilege, "sensitive_path": sensitive, "patch_state": patch, "vulnerability": vulnerability, "observed_at": iso(start)}
    assets = [asset("edge-vpn-01", "vpn", True, True, True, "pending", {"reference": "DEMO-ADV-001", "cvss": 6.5, "known_exploited": False}),
              asset("documents-01", "server", False, False, True, "applied"),
              asset("workstation-07", "endpoint", False, False, False, "applied")]
    events = [{"id": "evt-login-normal", "type": "login", "at": iso(start), "actor": "regular-staff@example.invalid", "session": "normal-session", "gateway_id": "edge-vpn-01", "success": True, "privileged": False, "device_trusted": True, "approved": True}]
    for i in range(16):
        events.append({"id": f"evt-normal-{i:03}", "type": "file_access", "at": iso(start + timedelta(seconds=i*15)), "actor": "regular-staff@example.invalid", "session": "normal-session", "asset_id": "documents-01", "file_id": f"normal-file-{i}", "sensitive": False, "bytes_read": 1024})
    events.append({"id": "evt-login-review", "type": "login", "at": iso(start + timedelta(minutes=6)), "actor": "vendor-maintenance@example.invalid", "session": "review-session", "gateway_id": "edge-vpn-01", "success": True, "privileged": True, "device_trusted": False, "approved": False})
    for i in range(130):
        events.append({"id": f"evt-review-{i:03}", "type": "file_access", "at": iso(start + timedelta(minutes=7, seconds=i*2)), "actor": "vendor-maintenance@example.invalid", "session": "review-session", "asset_id": "documents-01", "file_id": f"sensitive-document-{i}", "sensitive": i < 42, "bytes_read": 2048})
    return {"schema_version": 1, "as_of": iso(now), "assets": assets, "events": events}
