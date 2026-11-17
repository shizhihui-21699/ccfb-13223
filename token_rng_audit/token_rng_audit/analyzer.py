"""检验套件编排：运行全部检验，汇总为评估报告数据结构。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import checks as ck
from .findings import Finding, Status, Verdict, worst_status
from .predict import estimate_guesswork
from .tokens import SampleSet

# 检验顺序即报告中的展示顺序
_ALL_CHECKS = [
    ck.check_length,
    ck.check_duplicates,
    ck.check_structure,
    ck.check_character_distribution,
    ck.check_byte_frequency,
    ck.check_positional_entropy,
    ck.check_position_correlation,
    ck.check_serial_correlation,
    ck.check_time_correlation,
    ck.check_embedded_timestamp,
    ck.check_counter,
    ck.check_hash_counter,
    ck.check_lcg,
    ck.check_mt_seed,
    ck.check_markov,
]

_MIN_SAMPLES = 30
_GOOD_SAMPLES = 200


@dataclass
class AnalysisResult:
    sample: dict[str, Any]
    findings: list[Finding] = field(default_factory=list)
    verdict: Verdict | None = None
    guesswork: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample": self.sample,
            "findings": [f.to_dict() for f in self.findings],
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "guesswork": self.guesswork,
            "warnings": self.warnings,
        }


def analyze(samples: SampleSet) -> AnalysisResult:
    result = AnalysisResult(sample=_sample_meta(samples))
    if samples.n < _MIN_SAMPLES:
        result.warnings.append(
            f"仅 {samples.n} 个样本（建议 ≥{_GOOD_SAMPLES}），统计功效不足，"
            "结论可能漏报，弱缺陷需要更多样本才能稳定识别"
        )

    for fn in _ALL_CHECKS:
        finding = fn(samples)
        result.findings.append(finding)

    # 已验证的预测器决定有效熵折减
    penalty, reason = _prediction_penalty(samples, result.findings)
    g = estimate_guesswork(samples, penalty, reason)
    result.guesswork = {
        "effective_bits": g.effective_bits,
        "shannon_bits": g.positional_shannon_bits,
        "min_entropy_bits": g.positional_min_entropy_bits,
        "variable_positions": g.variable_positions,
        "alphabet_size": g.alphabet_size,
        "attack_times": g.human,
        "reduction_reasons": g.reduction_reasons,
    }

    # 用折减后的有效熵替换/强化 guesswork 检验结论
    for f in result.findings:
        if f.check_id == "guesswork":
            break
    else:
        result.findings.append(ck.check_guesswork(samples))
    _update_guesswork_finding(result, g)

    result.verdict = _build_verdict(samples, result.findings, g, penalty > 0)
    return result


def _sample_meta(s: SampleSet) -> dict[str, Any]:
    return {
        "source": s.source,
        "label": s.label or s.source,
        "count": s.n,
        "unique": s.unique_count,
        "encoding": s.encoding,
        "min_length": s.min_length,
        "max_length": s.max_length,
        "fixed_length": s.is_fixed_length,
        "alphabet_size": len(s.alphabet),
        "alphabet": "".join(s.alphabet),
        "has_timestamps": bool(s.timestamps),
        "examples": s.tokens[:3],
    }


def _prediction_penalty(s: SampleSet, findings: list[Finding]) -> tuple[float, str]:
    """已验证可预测时，按预测强度折减有效熵。"""
    by_id = {f.check_id: f for f in findings}
    if by_id.get("lcg", Finding("", "", Status.PASS, "")).status == Status.FAIL:
        return 9999.0, "LCG 参数已恢复，序列完全可计算，有效熵归零"
    if by_id.get("mt_seed", Finding("", "", Status.PASS, "")).status == Status.FAIL:
        return 9999.0, "MT19937 种子已恢复，随机流可完整复现，有效熵归零"
    if by_id.get("hash_counter", Finding("", "", Status.PASS, "")).status == Status.FAIL:
        return 9999.0, "令牌为哈希计数器，下一令牌可直接计算，有效熵归零"
    if by_id.get("counter", Finding("", "", Status.PASS, "")).status == Status.FAIL:
        return 9999.0, "明文计数器可枚举，有效熵归零"
    if by_id.get("markov", Finding("", "", Status.PASS, "")).status == Status.FAIL:
        m = by_id["markov"].metrics
        lift = m.get("lift", 1.0)
        # 预测提升越高折减越多，最多折减 75%
        bits = estimate_guesswork(s).positional_min_entropy_bits
        return bits * min(0.75, max(0.25, 1 - 1 / max(1.0, lift))), \
            f"字符可部分预测（提升 {lift:.1f} 倍），按预测强度折减有效熵"
    return 0.0, ""


def _update_guesswork_finding(result: AnalysisResult, g) -> None:
    for f in result.findings:
        if f.check_id == "guesswork":
            if g.effective_bits >= 128:
                f.status = Status.PASS
                f.summary = f"有效熵约 {g.effective_bits:.0f} bit，达到 128 bit 安全建议线"
            elif g.effective_bits >= 64:
                f.status = Status.WARN
                f.summary = f"有效熵约 {g.effective_bits:.0f} bit，低于建议值"
            else:
                f.status = Status.FAIL
                f.summary = f"有效熵仅约 {g.effective_bits:.0f} bit，猜测空间不足"
            f.detail = "；".join([g.human] + g.reduction_reasons)
            f.metrics.update({"effective_bits": g.effective_bits})
            return


def _build_verdict(
    s: SampleSet, findings: list[Finding], g, prediction_feasible: bool
) -> Verdict:
    counts = {"pass": 0, "warn": 0, "fail": 0, "info": 0}
    for f in findings:
        counts[f.status.value] += 1
    bits = g.effective_bits
    if prediction_feasible or bits < 32 or counts["fail"] >= 3:
        grade, grade_en = "可预测 / 不可接受", "PREDICTABLE"
        headline = "令牌生成方式存在可直接利用的缺陷，攻击者能够计算或枚举其他用户的令牌"
    elif bits < 64 or counts["fail"] >= 1:
        grade, grade_en = "弱", "WEAK"
        headline = "随机性不足，存在明确统计弱点，建议立即更换生成方式"
    elif bits < 128 or counts["warn"] >= 2:
        grade, grade_en = "中等", "MODERATE"
        headline = "通过部分检验但存在可疑信号或安全裕量不足，建议整改并复测"
    else:
        grade, grade_en = "强", "STRONG"
        headline = "各检验项未发现弱点，有效熵达到安全建议线，表现与 CSPRNG 输出一致"
    explanation = (
        f"共 {s.n} 个样本；通过 {counts['pass']} 项、警告 {counts['warn']} 项、"
        f"失败 {counts['fail']} 项、信息项 {counts['info']} 项。"
        f"估算有效熵 {bits:.1f} bit。注意：统计检验只能证伪不能证明安全，"
        "通过检验不替代代码层面对 secrets/os.urandom 的使用确认。"
    )
    return Verdict(
        grade, grade_en, headline, explanation,
        counts, bits, g.human, prediction_feasible,
    )
