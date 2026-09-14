"""Local fail-closed controls for real response delivery."""
from __future__ import annotations

from pathlib import Path



class EmergencyStopError(RuntimeError):
    """The operator's local kill switch is active or cannot be read."""


class EmergencyStop:
    """A separately managed sentinel that prevents the next real action.

    Presence means stop.  An inability to inspect the sentinel also stops the
    action, because an operator must never mistake an unavailable kill switch
    for a clear one.
    """

    def __init__(self, path: str | Path | None):
        self.path = Path(path).expanduser() if path is not None else None

    def assert_clear(self) -> None:
        if self.path is None:
            return
        try:
            self.path.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise EmergencyStopError("緊急停止ファイルを確認できないため、実操作を停止しました。") from exc
        raise EmergencyStopError("緊急停止が有効なため、実操作を停止しました。")
