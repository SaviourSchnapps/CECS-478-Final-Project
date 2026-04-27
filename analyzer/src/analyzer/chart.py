"""Render a bar chart of alert counts by notice type.

matplotlib is imported lazily so the rest of the pipeline still runs in
environments without it (e.g. minimal test images). When unavailable the
renderer logs a warning and skips chart output.
"""

from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger(__name__)


def render_alert_chart(by_note: dict[str, int], path: Path) -> bool:
    """Render a bar chart. Returns True if a file was written."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        log.warning("matplotlib not available — skipping chart render at %s", path)
        return False

    path.parent.mkdir(parents=True, exist_ok=True)
    if not by_note:
        fig, ax = plt.subplots(figsize=(6, 3))
        ax.text(0.5, 0.5, "no alerts in this run", ha="center", va="center")
        ax.axis("off")
        fig.savefig(path, dpi=120, bbox_inches="tight")
        plt.close(fig)
        return True

    items = sorted(by_note.items(), key=lambda kv: kv[1], reverse=True)
    labels = [k.replace("IDS::", "") for k, _ in items]
    values = [v for _, v in items]

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(labels, values, color="#4c72b0")
    ax.set_title("Alerts by detector")
    ax.set_ylabel("count")
    ax.set_xlabel("notice")
    for i, v in enumerate(values):
        ax.text(i, v, str(v), ha="center", va="bottom")
    fig.tight_layout()
    fig.savefig(path, dpi=120, bbox_inches="tight")
    plt.close(fig)
    return True
