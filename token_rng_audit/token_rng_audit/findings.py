"""检验结果的数据结构与严重级别判定。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Status(str, Enum):
    PASS = "pass"   # 未发现缺陷
    WARN = "warn"   # 可疑 / 证据不足
    FAIL = "fail"   # 存在可利用的弱点
    INFO = "info"   # 描述性信息，不参与判定


_STATUS_ORDER = {Status.PASS: 0, Status.INFO: 0, Status.WARN: 1, Status.FAIL: 2}


@dataclass
class Finding:
    """单项检验结论。"""

    check_id: str
    title: str
    status: Status
    summary: str
    detail: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)
    chart: Optional[dict[str, Any]] = None  # 报告层使用的图表描述

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "status": self.status.value,
            "summary": self.summary,
            "detail": self.detail,
            "metrics": self.metrics,
            "chart": self.chart,
        }


@dataclass
class Verdict:
    """整体评估结论。"""

    grade: str                       # 强 / 中等 / 弱 / 可预测
    grade_en: str
    headline: str
    explanation: str
    status_counts: dict[str, int]
    guesswork_bits: float
    guesswork_human: str
    prediction_feasible: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "grade": self.grade,
            "grade_en": self.grade_en,
            "headline": self.headline,
            "explanation": self.explanation,
            "status_counts": self.status_counts,
            "guesswork_bits": self.guesswork_bits,
            "guesswork_human": self.guesswork_human,
            "prediction_feasible": self.prediction_feasible,
        }


def worst_status(statuses: list[Status]) -> Status:
    return max(statuses, key=lambda s: _STATUS_ORDER[s]) if statuses else Status.INFO
