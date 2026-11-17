"""基础统计原语，全部基于标准库实现。"""

from __future__ import annotations

import math
from collections import Counter
from typing import Iterable, Sequence

# ---------------------------------------------------------------------------
# 熵
# ---------------------------------------------------------------------------


def shannon_entropy(symbols: Sequence) -> float:
    """以 2 为底的香农熵（单位：bit/符号）。空序列返回 0。"""
    n = len(symbols)
    if n == 0:
        return 0.0
    counts = Counter(symbols)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def entropy_from_counts(counts) -> float:
    total = sum(counts)
    if total == 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c:
            p = c / total
            h -= p * math.log2(p)
    return h


def min_entropy(symbols: Sequence) -> float:
    """最小熵 -log2(max p)：刻画“最可能符号”带来的最坏情况不确定性。"""
    n = len(symbols)
    if n == 0:
        return 0.0
    p_max = max(Counter(symbols).values()) / n
    return -math.log2(p_max)


def normalized_entropy(symbols: Sequence, alphabet_size: int) -> float:
    """归一化熵 H/Hmax，取值 [0,1]。alphabet_size<=1 时返回 0。"""
    if alphabet_size <= 1:
        return 0.0
    return shannon_entropy(symbols) / math.log2(alphabet_size)


def miller_madow_bias(sample_size: int, alphabet_observed: int) -> float:
    """Miller–Madow 一阶偏差修正量 (k_observed-1)/(2N)，单位 bit。"""
    if sample_size <= 1:
        return 0.0
    return max(0.0, (alphabet_observed - 1) / (2.0 * sample_size))


# ---------------------------------------------------------------------------
# 拟合优度：卡方
# ---------------------------------------------------------------------------


def chi_square_uniform(observed: Sequence[int]) -> tuple[float, int, float]:
    """对均匀分布做卡方检验。

    返回 (统计量, 自由度, 上侧 p 值)。p 值用正则化下侧不完全伽马函数计算。
    """
    k = len(observed)
    n = sum(observed)
    if k < 2 or n == 0:
        return 0.0, 0, 1.0
    expected = n / k
    stat = sum((o - expected) ** 2 / expected for o in observed)
    dof = k - 1
    p = _chi2_sf(stat, dof)
    return stat, dof, p


def _gammainc_reg(a: float, x: float) -> float:
    """正则化下侧不完全伽马函数 P(a,x)，数值配方（Numerical Recipes 风格）。"""
    if x < 0.0 or a <= 0.0:
        return 0.0
    if x == 0.0:
        return 0.0
    if x < a + 1.0:  # 级数展开
        ap, summ, delta = a, 1.0 / a, 1.0 / a
        for _ in range(200):
            ap += 1.0
            delta *= x / ap
            summ += delta
            if abs(delta) < abs(summ) * 1e-14:
                break
        return summ * math.exp(-x + a * math.log(x) - math.lgamma(a))
    # 连分式展开
    b = x + 1.0 - a
    c = 1e300
    d = 1.0 / b
    h = d
    for i in range(1, 201):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < 1e-300:
            d = 1e-300
        c = b + an / c
        if abs(c) < 1e-300:
            c = 1e-300
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-14:
            break
    return 1.0 - math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


def _chi2_sf(stat: float, dof: int) -> float:
    """卡方分布上侧概率 = 1 - P(dof/2, stat/2)。"""
    if stat <= 0.0:
        return 1.0
    return max(0.0, min(1.0, 1.0 - _gammainc_reg(dof / 2.0, stat / 2.0)))


# ---------------------------------------------------------------------------
# 相关性
# ---------------------------------------------------------------------------


def ranks(values: Sequence[float]) -> list[float]:
    """平均秩（处理并列）。"""
    order = sorted(range(len(values)), key=lambda i: values[i])
    out = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            out[order[k]] = avg
        i = j + 1
    return out


def pearson(x: Sequence[float], y: Sequence[float]) -> float:
    n = len(x)
    if n < 2 or n != len(y):
        return 0.0
    mx = sum(x) / n
    my = sum(y) / n
    sxx = sum((v - mx) ** 2 for v in x)
    syy = sum((v - my) ** 2 for v in y)
    sxy = sum((a - mx) * (b - my) for a, b in zip(x, y))
    denom = math.sqrt(sxx * syy)
    return sxy / denom if denom > 0 else 0.0


def spearman(x: Sequence[float], y: Sequence[float]) -> float:
    if len(x) < 2:
        return 0.0
    return pearson(ranks(x), ranks(y))


def cramers_v(observed: Sequence[Sequence[int]]) -> float:
    """二维列联表的 Cramér's V 关联强度，取值 [0,1]。

    使用 Bergsma (2013) 偏差修正，抑制稀疏/小样本列联表下 V 系统性偏高
    （未修正的 V 在独立的高维列联表上也常给出 0.3–0.5 的假关联）。
    """
    rows = [r for r in observed if sum(r) > 0]
    if len(rows) < 2:
        return 0.0
    n = sum(sum(r) for r in rows)
    if n == 0:
        return 0.0
    r_count = len(rows)
    c_count = len(rows[0])
    if c_count < 2:
        return 0.0
    row_totals = [sum(r) for r in rows]
    col_totals = [sum(rows[i][j] for i in range(r_count)) for j in range(c_count)]
    chi2 = 0.0
    for i in range(r_count):
        for j in range(c_count):
            e = row_totals[i] * col_totals[j] / n
            if e > 0:
                chi2 += (rows[i][j] - e) ** 2 / e
    phi2 = chi2 / n
    # Bergsma 修正
    r_hat = r_count - ((r_count - 1) ** 2) / (n - 1)
    c_hat = c_count - ((c_count - 1) ** 2) / (n - 1)
    phi2_adj = max(0.0, phi2 - ((r_count - 1) * (c_count - 1)) / (n - 1))
    k_hat = min(r_hat - 1, c_hat - 1)
    if k_hat <= 0:
        return 0.0
    return math.sqrt(phi2_adj / k_hat)


def cramers_v_sparse(pair_counts, row_counts, col_counts,
                     n: int, r_count: int, c_count: int) -> float:
    """稀疏版 Cramér's V：只遍历实际出现的符号组合，避免建完整 k×k 表。

    pair_counts: {(row_sym, col_sym): 频数}；row/col_counts 为边缘计数。
    """
    if n == 0 or r_count < 2 or c_count < 2:
        return 0.0
    chi2 = 0.0
    for (i, j), observed in pair_counts.items():
        e = row_counts[i] * col_counts[j] / n
        if e > 0:
            chi2 += (observed - e) ** 2 / e
    phi2 = chi2 / n
    r_hat = r_count - ((r_count - 1) ** 2) / (n - 1)
    c_hat = c_count - ((c_count - 1) ** 2) / (n - 1)
    phi2_adj = max(0.0, phi2 - ((r_count - 1) * (c_count - 1)) / (n - 1))
    k_hat = min(r_hat - 1, c_hat - 1)
    if k_hat <= 0:
        return 0.0
    return math.sqrt(phi2_adj / k_hat)


def runs_test(bits: Sequence[int]) -> tuple[float, float]:
    """游程检验：返回 (z 统计量, 双侧 p 值)。bits 只含 0/1。"""
    n = len(bits)
    if n < 2:
        return 0.0, 1.0
    n1 = sum(bits)
    n0 = n - n1
    if n0 == 0 or n1 == 0:
        return float("inf"), 0.0
    runs = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            runs += 1
    expected = 2 * n0 * n1 / n + 1
    var = (2 * n0 * n1 * (2 * n0 * n1 - n)) / (n * n * (n - 1))
    if var <= 0:
        return 0.0, 1.0
    z = (runs - expected) / math.sqrt(var)
    p = math.erfc(abs(z) / math.sqrt(2))
    return z, p


def normal_sf(z: float) -> float:
    """标准正态上侧概率。"""
    return 0.5 * math.erfc(abs(z) / math.sqrt(2))


# ---------------------------------------------------------------------------
# 序列工具
# ---------------------------------------------------------------------------


def numeric_values(symbols: Iterable) -> list:
    return list(symbols)


def safe_log2(n: int) -> float:
    return math.log2(n) if n > 0 else 0.0
