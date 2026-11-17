"""单项检验集合。每个函数接收 SampleSet，返回 Finding 或 Finding 列表。"""

from __future__ import annotations

import math
from collections import Counter

from . import stats
from .findings import Finding, Status
from .predict import (
    estimate_guesswork,
    markov_prediction,
    recover_lcg,
    recover_mt19937,
    test_embedded_timestamp,
    test_hash_counter,
    test_plain_counter,
)
from .structure import structural_fingerprint
from .tokens import SampleSet

P_ALPHA = 0.01  # 显著性水平（配合大样本，取 1% 以减少误报）


# ---------------------------------------------------------------------------
# 1. 长度与重复
# ---------------------------------------------------------------------------


def check_length(s: SampleSet) -> Finding:
    if s.is_fixed_length:
        return Finding(
            "length",
            "长度一致性",
            Status.PASS,
            f"全部 {s.n} 个令牌等长（{s.min_length} 字符）",
        )
    return Finding(
        "length",
        "长度一致性",
        Status.WARN,
        f"长度不固定：{s.min_length}–{s.max_length} 字符",
        "可变长度本身不代表脆弱，但位置类检验只覆盖公共长度部分，"
        "且长度差异可能泄露序号区间等信息。",
        {"min": s.min_length, "max": s.max_length},
    )


def check_duplicates(s: SampleSet) -> Finding:
    rate = s.duplicate_count / s.n
    if s.duplicate_count == 0:
        return Finding(
            "duplicates",
            "重复令牌",
            Status.PASS,
            f"{s.n} 个样本全部唯一",
            metrics={"unique": s.unique_count},
        )
    status = Status.FAIL if rate > 0.01 else Status.WARN
    return Finding(
        "duplicates",
        "重复令牌",
        status,
        f"出现 {s.duplicate_count} 个重复（{rate:.2%}）",
        "重置链接/会话令牌任何重复都意味着同一凭证可被重放，应视为严重缺陷。",
        {"duplicate_rate": rate},
    )


# ---------------------------------------------------------------------------
# 2. 字符分布
# ---------------------------------------------------------------------------


def check_character_distribution(s: SampleSet) -> Finding:
    chars = s.all_chars()
    counter = Counter(chars)
    alphabet_size = len(s.alphabet)
    observed = [counter.get(c, 0) for c in s.alphabet]
    chi2, dof, p = stats.chi_square_uniform(observed)
    h = stats.shannon_entropy(chars)
    hmax = math.log2(alphabet_size) if alphabet_size > 1 else 0.0
    ratio = h / hmax if hmax else 0.0
    # 期望频次过低时卡方不可靠
    low_expected = (len(chars) / max(1, alphabet_size)) < 5
    if low_expected:
        status = Status.WARN
        note = "字母表相对样本量过大，卡方检验功效不足，结论仅作参考"
    elif p < 0.001 or ratio < 0.95:
        status = Status.FAIL
        note = "字符频率显著偏离均匀分布，存在偏好字符"
    elif p < 0.01 or ratio < 0.985:
        status = Status.WARN
        note = "字符频率轻度偏离均匀分布（也可能是多重检验的随机波动）"
    else:
        status = Status.PASS
        note = "字符频率与均匀分布一致"
    chart = {
        "kind": "bar",
        "title": "字符频率分布",
        "x": s.alphabet,
        "y": observed,
        "expected": len(chars) / max(1, alphabet_size),
    }
    return Finding(
        "char_distribution",
        "字符分布均匀性（卡方）",
        status,
        note,
        f"香农熵 {h:.2f}/{hmax:.2f} bit/字符（{ratio:.1%}）；"
        f"卡方={chi2:.2f}，dof={dof}，p={p:.4g}",
        {"chi2": chi2, "dof": dof, "p": p, "entropy_ratio": ratio,
         "alphabet_size": alphabet_size},
        chart,
    )


def check_byte_frequency(s: SampleSet) -> Finding:
    if len(s.decoded_bytes) < 256 or not s.byte_stream:
        return Finding(
            "byte_frequency",
            "字节级频率检验",
            Status.INFO,
            "样本不足或无法按 hex/base64 解码，跳过字节级检验",
        )
    stream = s.byte_stream
    observed = [stream.count(b) for b in range(256)]
    chi2, dof, p = stats.chi_square_uniform(observed)
    h = stats.shannon_entropy(list(stream))
    ratio = h / 8.0
    if p < 0.001 or ratio < 0.97:
        status = Status.FAIL
        note = "字节频率显著偏离均匀分布"
    elif p < 0.01 or ratio < 0.99:
        status = Status.WARN
        note = "字节频率轻度偏离"
    else:
        status = Status.PASS
        note = "字节频率与均匀分布一致"
    chart = {
        "kind": "histogram",
        "title": "字节值频率（0–255）",
        "y": observed,
    }
    return Finding(
        "byte_frequency",
        "字节级频率检验",
        status,
        note,
        f"解码后共 {len(stream)} 字节；熵 {h:.3f}/8 bit（{ratio:.2%}）；"
        f"卡方={chi2:.1f}，p={p:.4g}",
        {"chi2": chi2, "p": p, "entropy_ratio": ratio, "bytes": len(stream)},
        chart,
    )


# ---------------------------------------------------------------------------
# 3. 逐位置熵与位置间相关性
# ---------------------------------------------------------------------------


def check_positional_entropy(s: SampleSet) -> Finding:
    rows = []
    weak_positions = []
    for p in range(s.min_length):
        col = s.positional[p]
        h = stats.shannon_entropy(col)
        hmin = stats.min_entropy(col)
        observed_symbols = len(set(col))
        rows.append({"position": p, "entropy": h, "min_entropy": hmin,
                     "symbols": observed_symbols})
        if hmin < math.log2(len(s.alphabet)) * 0.5:
            weak_positions.append(p)
    total_h = sum(r["entropy"] for r in rows)
    total_hmin = sum(r["min_entropy"] for r in rows)
    if weak_positions:
        status = Status.FAIL if len(weak_positions) > s.min_length / 3 else Status.WARN
        note = f"{len(weak_positions)} 个位置熵明显偏低：{weak_positions[:12]}"
    else:
        status = Status.PASS
        note = "各位置字符均保持接近满熵"
    chart = {
        "kind": "line",
        "title": "逐位置香农熵 / 最小熵",
        "x": [r["position"] for r in rows],
        "series": [
            {"name": "香农熵", "y": [r["entropy"] for r in rows]},
            {"name": "最小熵", "y": [r["min_entropy"] for r in rows]},
        ],
        "hmax": math.log2(len(s.alphabet)),
    }
    return Finding(
        "positional_entropy",
        "逐位置熵",
        status,
        note,
        f"逐位置香农熵合计 {total_h:.1f} bit，最小熵合计 {total_hmin:.1f} bit",
        {"total_shannon": total_h, "total_min_entropy": total_hmin,
         "weak_positions": weak_positions, "rows": rows},
        chart,
    )


def check_position_correlation(s: SampleSet) -> Finding:
    """相邻位置 Cramér's V + 非相邻位置对抽样扫描（稀疏计数，线性开销）。"""
    if s.min_length < 2 or s.n < 20:
        return Finding("pos_corr", "位置间相关性", Status.INFO, "样本或长度不足，跳过")

    def pair_v(p: int, q: int) -> float:
        pairs: Counter = Counter()
        rows: Counter = Counter()
        cols: Counter = Counter()
        for tok in s.tokens:
            a, b = tok[p], tok[q]
            pairs[(a, b)] += 1
            rows[a] += 1
            cols[b] += 1
        return stats.cramers_v_sparse(
            pairs, rows, cols, s.n, len(rows), len(cols))

    adjacent = [pair_v(p, p + 1) for p in range(s.min_length - 1)]
    max_idx = max(range(len(adjacent)), key=lambda i: adjacent[i])
    max_pair = (adjacent[max_idx], max_idx, max_idx + 1)

    # 非相邻抽样：长令牌时控制位置对数量
    step = max(1, s.min_length // 16)
    for p in range(0, s.min_length - 2, step):
        for q in range(p + 2, min(s.min_length, p + 2 + 8 * step), step):
            v = pair_v(p, q)
            if v > max_pair[0]:
                max_pair = (v, p, q)
    v_max, p1, p2 = max_pair
    avg_v = sum(adjacent) / len(adjacent)
    if v_max > 0.5:
        status = Status.FAIL
        note = f"位置 {p1} 与 {p2} 存在强关联（Cramér's V={v_max:.3f}），字符不独立"
    elif v_max > 0.3:
        status = Status.WARN
        note = f"检测到中等强度位置关联（最大 V={v_max:.3f}）"
    else:
        status = Status.PASS
        note = f"位置间未发现显著关联（相邻位置平均 V={avg_v:.3f}）"
    chart = {
        "kind": "line",
        "title": "相邻位置 Cramér's V",
        "x": list(range(len(adjacent))),
        "series": [{"name": "Cramér's V", "y": adjacent}],
    }
    return Finding(
        "pos_corr",
        "位置间相关性（Cramér's V）",
        status,
        note,
        f"相邻位置平均 V={avg_v:.3f}，最大 V={v_max:.3f}（位置 {p1}↔{p2}）",
        {"max_v": v_max, "avg_adjacent_v": avg_v,
         "max_pair": [p1, p2], "adjacent": adjacent},
        chart,
    )


# ---------------------------------------------------------------------------
# 4. 序号关联（游程 + 自相关）
# ---------------------------------------------------------------------------


def check_serial_correlation(s: SampleSet) -> Finding:
    if s.n < 12 or not s.byte_positions:
        return Finding("serial", "序号关联（游程/自相关）", Status.INFO, "样本不足，跳过")
    # 取每个令牌首字节的最高位做游程检验
    first_bytes = [row[0] for row in s.byte_positions]
    bits = [(b >> 7) & 1 for b in first_bytes]
    z, p_runs = stats.runs_test(bits)
    # 整数值自相关（滞后 1）
    spear = None
    if s.int_values is not None and s.n >= 8:
        x = s.int_values[:-1]
        y = s.int_values[1:]
        spear = stats.spearman(x, y)
    problems = []
    if p_runs < P_ALPHA:
        problems.append(f"游程检验异常（z={z:.2f}, p={p_runs:.4g}）")
    if spear is not None and abs(spear) > 0.8:
        problems.append(f"相邻令牌整数强{('正' if spear > 0 else '负')}相关（Spearman={spear:.3f}）")
    if problems:
        status = Status.FAIL
        note = "；".join(problems)
    else:
        status = Status.PASS
        note = "未发现明显序列自相关"
    return Finding(
        "serial",
        "序号关联（游程/自相关）",
        status,
        note,
        f"游程 z={z:.2f}, p={p_runs:.4g}"
        + (f"；Spearman(滞后1)={spear:.3f}" if spear is not None else ""),
        {"runs_z": z, "runs_p": p_runs, "spearman_lag1": spear},
    )


# ---------------------------------------------------------------------------
# 5. 时间关联
# ---------------------------------------------------------------------------


def check_time_correlation(s: SampleSet) -> Finding:
    if len(s.timestamps) != s.n or s.n < 8 or s.int_values is None:
        return Finding("time_corr", "时间关联", Status.INFO,
                       "缺少采集时间戳或令牌不可数值化，跳过")
    ts = s.timestamps
    vals = s.int_values
    rho = stats.spearman(ts, vals)
    # 与时间戳低位的关联（常见“时间戳+随机后缀”里随机段放在高位的反向情形）
    low32 = [v & 0xFFFFFFFF for v in vals]
    rho_low = stats.spearman(ts, low32)
    if abs(rho) > 0.9 or abs(rho_low) > 0.9:
        status = Status.FAIL
        note = "令牌数值与采集时间高度相关，疑似时间戳驱动生成"
    elif abs(rho) > 0.6 or abs(rho_low) > 0.6:
        status = Status.WARN
        note = "令牌数值与时间存在中等相关，建议复核生成逻辑"
    else:
        status = Status.PASS
        note = "令牌数值与采集时间无显著相关"
    chart = {
        "kind": "scatter",
        "title": "采集时间 vs 令牌整数值",
        "x": [t - ts[0] for t in ts],
        "y": vals,
        "x_label": "相对采集时间（秒）",
    }
    return Finding(
        "time_corr",
        "时间关联（Spearman）",
        status,
        note,
        f"Spearman(时间, 整数)={rho:.3f}；Spearman(时间, 低32位)={rho_low:.3f}",
        {"spearman_time_value": rho, "spearman_time_low32": rho_low},
        chart,
    )


# ---------------------------------------------------------------------------
# 6. 结构指纹
# ---------------------------------------------------------------------------


def check_structure(s: SampleSet) -> Finding:
    fp = structural_fingerprint(s.tokens)
    if fp is None:
        return Finding("structure", "结构指纹", Status.PASS, "未发现特殊结构（视为不透明随机串）")
    if fp["type"] == "uuid" and fp.get("version") == 1:
        status = Status.FAIL
    elif fp["type"] in ("jwt-like",):
        status = Status.WARN
    else:
        status = Status.WARN
    return Finding(
        "structure",
        "结构指纹",
        status,
        f"识别为 {fp['type']}：{fp['note']}",
        metrics=fp,
    )


# ---------------------------------------------------------------------------
# 7. 预测性检验（一组）
# ---------------------------------------------------------------------------


def check_markov(s: SampleSet) -> Finding:
    r = markov_prediction(s)
    if r.test_samples == 0:
        return Finding("markov", "字符级预测（马尔可夫）", Status.INFO, "样本不足，跳过")
    lift = r.markov_accuracy / r.baseline if r.baseline else 0.0
    status = Status.FAIL if r.predictable else Status.PASS
    return Finding(
        "markov",
        "字符级预测（一阶马尔可夫）",
        status,
        (f"留出集字符预测准确率 {r.markov_accuracy:.2%}，"
         f"是均匀猜测基线 {r.baseline:.2%} 的 {lift:.1f} 倍")
        if not r.predictable
        else f"下一令牌字符可被预测：准确率 {r.markov_accuracy:.2%}（基线 {r.baseline:.2%}）",
        f"逐位置众数基线准确率 {r.marginal_accuracy:.2%}；测试样本 {r.test_samples} 个令牌",
        {"markov_accuracy": r.markov_accuracy,
         "marginal_accuracy": r.marginal_accuracy,
         "baseline": r.baseline, "lift": lift},
    )


def check_lcg(s: SampleSet) -> Finding:
    if s.int_values is None or s.n < 10:
        return Finding("lcg", "LCG 参数恢复", Status.INFO,
                       "令牌无法整体数值化或样本不足，跳过")
    r = recover_lcg(s.int_values)
    if not r.recovered:
        return Finding("lcg", "LCG 参数恢复", Status.PASS,
                       "未能用线性同余模型拟合该序列",
                       r.method or "",
                       {"heldout_accuracy": r.heldout_accuracy})
    return Finding(
        "lcg",
        "LCG 参数恢复",
        Status.FAIL,
        f"成功恢复线性同余参数，留出段预测准确率 {r.heldout_accuracy:.0%}，下一个令牌可直接计算",
        f"x' = (a·x + c) mod m；m={r.modulus}，a={r.multiplier}，c={r.increment}",
        {"modulus": r.modulus, "multiplier": r.multiplier,
         "increment": r.increment, "heldout_accuracy": r.heldout_accuracy},
    )


def check_mt_seed(s: SampleSet) -> Finding:
    if s.int_values is None:
        return Finding("mt_seed", "MT19937 时间种子恢复", Status.INFO,
                       "令牌无法数值化，跳过")
    r = recover_mt19937(s)
    if not r.recovered:
        return Finding("mt_seed", "MT19937 时间种子恢复", Status.PASS,
                       f"在时间窗口与常见弱种子（共试 {r.candidates_tried} 个候选）内未恢复种子")
    return Finding(
        "mt_seed",
        "MT19937 时间种子恢复",
        Status.FAIL,
        f"恢复出种子 {r.seed}（{r.seed_kind}），可重建完整随机流，预测准确率 {r.heldout_accuracy:.0%}",
        "random.Random 等非 CSPRNG 一旦种子可猜（时间/PID/自增），整个输出序列可复现。",
        {"seed": r.seed, "seed_kind": r.seed_kind,
         "heldout_accuracy": r.heldout_accuracy,
         "candidates_tried": r.candidates_tried},
    )


def check_hash_counter(s: SampleSet) -> Finding:
    r = test_hash_counter(s)
    if not r.matched:
        return Finding("hash_counter", "哈希计数器假设", Status.PASS,
                       "不符合 hash(递增计数器) 模式")
    return Finding(
        "hash_counter",
        "哈希计数器假设",
        Status.FAIL,
        f"令牌 = {r.algorithm}(counter)，起始计数器={r.start_counter}，"
        "哈希不增加不可预测性，下一个令牌可直接算出",
        f"编码 {r.encoding}；留出验证准确率 {r.heldout_accuracy:.0%}",
        {"algorithm": r.algorithm, "start": r.start_counter,
         "heldout_accuracy": r.heldout_accuracy},
    )


def check_counter(s: SampleSet) -> Finding:
    r = test_plain_counter(s)
    if not r.is_counter:
        return Finding("counter", "明文计数器识别", Status.PASS,
                       "未发现恒定步长的递增模式",
                       metrics={"monotonic_ratio": r.monotonic_ratio})
    return Finding(
        "counter",
        "明文计数器识别",
        Status.FAIL,
        f"令牌为步长 {r.delta} 的递增计数器，预测准确率 {r.heldout_accuracy:.0%}",
        "计数器令牌可被枚举，攻击者只需遍历相邻值即可劫持其他用户的链接/会话。",
        {"delta": r.delta, "heldout_accuracy": r.heldout_accuracy,
         "monotonic_ratio": r.monotonic_ratio},
    )


def check_embedded_timestamp(s: SampleSet) -> Finding:
    r = test_embedded_timestamp(s)
    if not r.found:
        return Finding("embed_ts", "内嵌时间戳识别", Status.PASS,
                       "未在令牌中发现与采集时间吻合的时间戳字段")
    return Finding(
        "embed_ts",
        "内嵌时间戳识别",
        Status.WARN,
        r.detail,
        "时间戳字段可预测，应保证其余随机字段至少 128 bit 且来自 CSPRNG。",
        {"unit": r.unit, "positions": r.positions},
    )


# ---------------------------------------------------------------------------
# 8. 猜测空间（analyzer 在拿到全部结论后调用，这里提供独立版本）
# ---------------------------------------------------------------------------


def check_guesswork(s: SampleSet) -> Finding:
    g = estimate_guesswork(s)
    if g.effective_bits >= 128:
        status = Status.PASS
        note = f"有效熵约 {g.effective_bits:.0f} bit，达到现代会话令牌建议下限（128 bit）"
    elif g.effective_bits >= 64:
        status = Status.WARN
        note = f"有效熵约 {g.effective_bits:.0f} bit，离线暴力破解风险升高"
    else:
        status = Status.FAIL
        note = f"有效熵仅约 {g.effective_bits:.0f} bit，猜测空间过小"
    return Finding(
        "guesswork",
        "有效熵与猜测空间",
        status,
        note,
        "；".join([g.human] + g.reduction_reasons),
        {"effective_bits": g.effective_bits,
         "shannon_bits": g.positional_shannon_bits,
         "variable_positions": g.variable_positions,
         "alphabet_size": g.alphabet_size,
         "attack_times": g.human},
    )
