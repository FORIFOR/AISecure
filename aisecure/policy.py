"""Allowlisted simulation-only response plans. No shell or real admin credentials."""
from typing import Protocol

PLANS = {
    "correlation": {"action": "revoke_session", "title": "対象セッションの失効を検討", "impact": "対象の保守作業が中断する可能性があります。", "prechecks": ["当該ログが真正か、現在もセッションが有効かを管理画面で確認", "正規の保守作業でないことを担当者・作業申請と照合", "証跡を別保管し、再認証・復旧の責任者を決定"], "recovery": "実運用では資格情報を再発行・再認証し、承認済み端末から復旧。セッション失効自体は取り消せません。",
        "title_en": "Consider revoking the target session", "impact_en": "The target maintenance work may be interrupted.", "prechecks_en": ["Confirm in the admin console that the log is authentic and the session is still active", "Cross-check against the operator and change request that this is not authorised maintenance", "Preserve the evidence separately and assign an owner for re-authentication and recovery"], "recovery_en": "In real operation, reissue credentials, re-authenticate, and recover from an approved device. Session revocation itself cannot be undone."},
    "exposure": {"action": "restrict_remote_access", "title": "接続経路の制限と修正計画を確認", "impact": "外部の保守接続が利用できなくなる可能性があります。", "prechecks": ["機器・バージョンとベンダーの影響条件を照合", "代替の管理経路と承認済みの保守時間を確認", "機器構成・ログを保全し、機器別の復旧手順を確認"], "recovery": "実運用では承認済みの設定差分を戻し、正規の通信と監査ログを確認。脆弱性の放置に戻さないこと。",
        "title_en": "Review access restriction and a patch plan", "impact_en": "External maintenance connectivity may become unavailable.", "prechecks_en": ["Match the device and version against the vendor's affected conditions", "Confirm an alternative management path and an approved maintenance window", "Preserve device config and logs, and review the per-device recovery procedure"], "recovery_en": "In real operation, restore the approved config diff and verify legitimate traffic and audit logs. Do not revert to leaving the vulnerability unpatched."},
}
DEFAULT = {"action": "review_evidence", "title": "証跡と正規作業を照合", "impact": "この計画は調査のみで、通信・アカウントを変更しません。", "prechecks": ["元ログとイベントIDを照合", "業務上の正当な理由がないか確認"], "recovery": "設定変更なし。",
    "title_en": "Cross-check the evidence against authorised work", "impact_en": "This plan is investigation only; it changes no traffic or account.", "prechecks_en": ["Match the source logs against the event IDs", "Check for a legitimate business reason"], "recovery_en": "No configuration change."}


class ResponseAdapter(Protocol):
    def simulate(self, plan: dict) -> dict: ...


class SimulationAdapter:
    def simulate(self, plan: dict) -> dict:
        if plan["action"] not in {"revoke_session", "restrict_remote_access", "review_evidence"}:
            raise ValueError("未許可のアクションです。")
        return {"status": "simulated", "executed": False, "adapter": "simulation-only", "message": "シミュレーション完了。実際の機器・アカウントには一切変更していません。"}


def plan_for(finding: dict) -> dict:
    return {**PLANS.get(finding["kind"], DEFAULT), "finding_id": finding["id"], "target": finding.get("actor", finding.get("asset_id", "evidence")), "requires_approval": True, "execution_mode": "simulation_only", "automatic_execution": False}
