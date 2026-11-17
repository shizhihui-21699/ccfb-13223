"""预测性检验：判断令牌能否被实际预测，而不只是“熵看起来低”。

包含：
  - 位置条件马尔可夫预测器（与逐位置众数基线对比）
  - 线性同余生成器 (LCG) 参数恢复：由输出差分的 gcd 恢复模数，再求 a/c
  - MT19937 时间种子恢复（random.Random，种子=秒/毫秒时间戳及常见弱种子）
  - 哈希计数器假设（md5/sha1/sha256 of 递增整数）
  - 明文计数器 / 时间戳嵌入识别
  - 有效猜测空间估算（逐位置最小熵之和 + 结构折减 + 已验证预测器折减）
"""

from __future__ import annotations

import hashlib
import math
import random
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Optional

from . import stats
from .tokens import SampleSet


# ---------------------------------------------------------------------------
# 字符级预测
# ---------------------------------------------------------------------------


@dataclass
class MarkovResult:
    marginal_accuracy: float       # 逐位置众数预测器
    markov_accuracy: float         # 一阶位置条件预测器
    baseline: float                # 均匀猜测基线 1/字母表
    test_samples: int
    predictable: bool


def markov_prediction(samples: SampleSet, split: float = 0.8) -> MarkovResult:
    n = samples.n
    if n < 10 or samples.min_length < 2:
        return MarkovResult(0.0, 0.0, 0.0, 0, False)
    cut = max(2, int(n * split))
    train, test = samples.tokens[:cut], samples.tokens[cut:]
    plen = samples.min_length
    alphabet_size = len(samples.alphabet) or 1

    # 逐位置边缘分布
    marginals: list[Counter] = [Counter() for _ in range(plen)]
    # 条件分布：(位置 p, 前一字符) -> Counter(当前字符)
    cond: dict[tuple[int, str], Counter] = defaultdict(Counter)
    for tok in train:
        for p in range(plen):
            marginals[p][tok[p]] += 1
            if p > 0:
                cond[(p, tok[p - 1])][tok[p]] += 1
    marginal_pred = [c.most_common(1)[0][0] if c else None for c in marginals]
    # 可变位置：训练集该位置出现过 ≥2 种符号，固定位置不参与预测能力评估
    variable_pos = [p for p in range(plen) if len(marginals[p]) >= 2]
    if not variable_pos:
        return MarkovResult(1.0, 1.0, 1.0, len(test), False)

    m_hits = k_hits = total = 0
    for tok in test:
        for p in variable_pos:
            total += 1
            if marginal_pred[p] == tok[p]:
                m_hits += 1
            if p == 0:
                guess = marginal_pred[0]
            else:
                table = cond.get((p, tok[p - 1]))
                guess = table.most_common(1)[0][0] if table else marginal_pred[p]
            if guess == tok[p]:
                k_hits += 1
    baseline = 1.0 / alphabet_size
    ma = m_hits / total if total else 0.0
    ka = k_hits / total if total else 0.0
    # 条件预测相对众数基线有实质增量（+15 个百分点且相对提升 30%），
    # 且绝对准确率明显高于均匀猜测，才算可预测
    predictable = (ka - ma) > 0.15 and ka > ma * 1.3 and ka > baseline * 2
    return MarkovResult(ma, ka, baseline, len(test), predictable)


# ---------------------------------------------------------------------------
# LCG 恢复
# ---------------------------------------------------------------------------


@dataclass
class LCGResult:
    recovered: bool
    modulus: Optional[int]
    multiplier: Optional[int]
    increment: Optional[int]
    heldout_accuracy: float
    method: str = ""


def _solve_mod_linear(a: int, b: int, m: int) -> list[int]:
    """解同余方程 a·x ≡ b (mod m)，返回所有解。支持非互素情形。"""
    g = math.gcd(a, m)
    if b % g != 0:
        return []
    a1, b1, m1 = a // g, b // g, m // g
    if m1 == 1:
        return [0]
    x0 = (b1 * pow(a1, -1, m1)) % m1
    return sorted((x0 + k * m1) % m for k in range(g))


def _recover_ac(x0: int, x1: int, x2: int, modulus: int) -> list[tuple[int, int]]:
    """由三个连续输出求 (a, c)：c = x1 - a·x0；a(x1-x0) ≡ (x2-x1) (mod m)。"""
    d0 = x1 - x0
    d1 = x2 - x1
    out = []
    for a in _solve_mod_linear(d0, d1, modulus):
        c = (x1 - a * x0) % modulus
        out.append((a, c))
    return out


def recover_lcg(values: list[int], heldout: float = 0.25) -> LCGResult:
    """从整数输出序列恢复 LCG 参数 x' = (a*x + c) mod m。

    同时支持素模数（差分可逆，直接求逆）与 2 的幂模数（同余方程多解，
    逐位提升后用后续输出筛选），模数候选来自输出差分的 gcd。
    """
    n = len(values)
    if n < 8:
        return LCGResult(False, None, None, None, 0.0)
    # LCG 恢复只对 ≤64 bit 的输出有实际意义；更宽的整数（如误解码的结构化
    # 令牌）会让同余方程的解数量组合爆炸，直接放弃
    if max(abs(v) for v in values) >= (1 << 64):
        return LCGResult(False, None, None, None, 0.0, "输出位宽 >64 bit，跳过 LCG 恢复")
    cut = n - max(2, int(n * heldout))
    train, test = values[:cut], values[cut:]
    max_val = max(max(abs(v) for v in train), 1)
    diffs = [train[i + 1] - train[i] for i in range(len(train) - 1)]
    if len(diffs) < 4:
        return LCGResult(False, None, None, None, 0.0)
    t_vals = [
        abs(diffs[i + 2] * diffs[i] - diffs[i + 1] ** 2)
        for i in range(len(diffs) - 2)
    ]
    t_vals = [v for v in t_vals if v != 0]
    if not t_vals:
        return LCGResult(False, None, None, None, 0.0)
    g = 0
    for v in t_vals:
        g = math.gcd(g, v)
    if g == 0:
        return LCGResult(False, None, None, None, 0.0)

    # 候选模数：gcd 本身、其 2 的幂因子、以及常见标准位宽（由输出量级推断）
    candidates = {g}
    p2 = 1
    while g % 2 == 0:
        g //= 2
        p2 *= 2
        candidates.add(p2)
    for width in (16, 32, 48, 64):
        m = 1 << width
        if m > max_val:
            candidates.add(m)
    candidates = {m for m in candidates if m > max_val and m >= 0x10000}

    verify_n = min(6, len(train) - 3)
    best: Optional[LCGResult] = None
    checked = 0
    for modulus in sorted(candidates):
        solutions = _recover_ac(train[0], train[1], train[2], modulus)
        # 解过多说明模数与数据不匹配（常见于非 LCG 序列），限制枚举规模
        if len(solutions) > 64:
            solutions = solutions[:64]
        for a, c in solutions:
            checked += 1
            if checked > 4096:  # 总尝试上限，防止病态输入拖垮分析
                return best or LCGResult(False, None, None, None, 0.0,
                                         "候选解过多，已终止 LCG 恢复")
            if a <= 1:  # 平凡解 a=0/1 不算有效恢复
                continue
            x = train[verify_n - 1]
            ok = 0
            for i in range(verify_n):
                x = (a * x + c) % modulus
                if x == train[verify_n + i] if verify_n + i < len(train) else False:
                    ok += 1
            if ok < min(3, verify_n):
                continue
            # 留出段验证
            x = train[-1]
            preds = []
            for _ in test:
                x = (a * x + c) % modulus
                preds.append(x)
            acc = sum(1 for p, t in zip(preds, test) if p == t) / len(test)
            if acc >= 0.9 and (best is None or modulus < (best.modulus or 1 << 64)):
                best = LCGResult(True, modulus, a, c, acc,
                                 "差分 gcd + 模线性方程恢复")
    if best is not None:
        return best
    return LCGResult(False, None, None, None, 0.0,
                     f"已得到差分 gcd 候选但未通过留出验证（gcd={g if p2 == 1 else p2}）")


# ---------------------------------------------------------------------------
# MT19937 时间种子恢复
# ---------------------------------------------------------------------------

_WEAK_SEEDS = [0, 1, 2, 42, 1337, 2024, 2025, 2026]


@dataclass
class MTResult:
    recovered: bool
    seed: Optional[int]
    seed_kind: str
    heldout_accuracy: float
    candidates_tried: int


def recover_mt19937(
    samples: SampleSet, window_sec: int = 300, max_counter: int = 1024
) -> MTResult:
    """恢复 MT19937 弱种子。

    支持两种缺陷形态：
      A. 单个种子生成连续输出（进程启动时播种一次）；
      B. 每个令牌单独播种，种子=时间戳（或时间戳×1000+小计数器）。
    对 B 逐令牌在时间窗口内搜索种子，以命中率作为“可复现性”证据；
    命中后还可用该种子验证同种子的后续输出（形态 A）。
    """
    if samples.int_values is None or samples.n < 3:
        return MTResult(False, None, "", 0.0, 0)
    values = samples.int_values
    observed_bits = max(1, values[0].bit_length())
    # MT 单次/双次输出实际只覆盖 32/64 bit；超过 128 bit 的整数不可能由
    # getrandbits 直接产生，穷举种子没有意义
    if observed_bits > 128:
        return MTResult(False, None, "", 0.0, 0)
    # 关键：不能用首值的实际 bit_length 当输出宽度——高位为 0 时它会小于
    # 标称宽度，导致 getrandbits 的结果与真实生成不一致。对 32/64 两个
    # getrandbits 的标准输出宽度都尝试匹配。
    candidate_widths = [w for w in (32, 64) if w >= observed_bits]
    t0 = samples.timestamps[0] if samples.timestamps else time.time()
    tried = 0

    for bits in candidate_widths:
        outcome = _attempt_mt_recovery(
            samples, values, bits, t0, tried, window_sec, max_counter)
        tried = outcome.candidates_tried
        if outcome.recovered:
            return outcome
    return MTResult(False, None, "", 0.0, tried)


def _attempt_mt_recovery(samples, values, bits: int, t0: float,
                         tried_in: int, window_sec: int,
                         max_counter: int) -> MTResult:
    """在指定输出宽度下运行完整的 MT 种子恢复（形态 A 与形态 B）。"""
    tried = tried_in

    # 形态 A：单一固定/时间种子生成连续输出
    def try_stream_seed(seed: int) -> bool:
        rng = random.Random(seed)
        return all(rng.getrandbits(bits) == w
                   for w in values[: min(4, len(values))])

    for seed in _WEAK_SEEDS:
        tried += 1
        if try_stream_seed(seed):
            return _mt_verify(seed, "固定弱种子", values, bits, tried)
    base = int(t0)
    for delta in range(-window_sec, window_sec + 1):
        sec = base + delta
        for seed in (sec, sec * 1000):
            tried += 1
            if try_stream_seed(seed):
                kind = "秒级时间戳" if seed < 10_000_000_000 else "毫秒时间戳"
                return _mt_verify(seed, kind, values, bits, tried)

    # 形态 B：逐令牌弱种子（带采集时间戳才可靠）。
    # 两阶段：先用首令牌在小窗口内穷举确认种子构造公式，
    # 再按采集序号直接推算后续种子并验证，避免逐令牌全量穷举。
    if not samples.timestamps:
        return MTResult(False, None, "", 0.0, tried)
    first_seed, first_kind, tried_b = _discover_per_token_seed(
        values[0], int(samples.timestamps[0]), bits, max_counter)
    tried += tried_b
    if first_seed is None:
        return MTResult(False, None, "", 0.0, tried)

    if first_kind == "sec_plus_counter":
        k0 = first_seed % 1000
        base_sec = first_seed // 1000
        verify_n = min(samples.n, 100)
        hits = 0
        for i in range(verify_n):
            # 计数器按相对偏移递增；秒以发现阶段的基准秒为锚点（批量采集时
            # 各令牌采集时间戳可能相同，不能用它反推生成秒），并留少量抖动
            expect_k = k0 + i
            if _matches_per_token_anchored(
                    values[i], base_sec, expect_k, bits):
                hits += 1
        acc = hits / verify_n
        if acc >= 0.8:
            return MTResult(True, first_seed,
                            "逐令牌弱种子（秒级时间戳×1000+计数器）",
                            acc, tried + verify_n)
    else:  # 纯时间戳种子（秒或毫秒）
        verify_n = min(samples.n, 100)
        hits = sum(
            1 for i in range(verify_n)
            if _matches_plain_ts(values[i], samples.timestamps[i],
                                 bits, first_kind == "millis")
        )
        acc = hits / verify_n
        if acc >= 0.8:
            return MTResult(True, first_seed,
                            f"逐令牌弱种子（{first_kind}时间戳）",
                            acc, tried + verify_n)
    return MTResult(False, None, "", 0.0, tried)


def _discover_per_token_seed(want: int, sec0: int, bits: int,
                             max_counter: int) -> tuple[Optional[int], str, int]:
    """对单个令牌穷举种子，确认其构造方式。

    秒窗口取 ±5，覆盖 HTTP 往返与批量生成导致的采集/生成时间差。
    """
    tried = 0
    for delta in range(-5, 6):
        sec = sec0 + delta
        for seed in (sec, sec * 1000):
            tried += 1
            if random.Random(seed).getrandbits(bits) == want:
                kind = "millis" if seed >= 10_000_000_000 else "seconds"
                return seed, kind, tried
        for k in range(max_counter):
            seed = sec * 1000 + k
            tried += 1
            if random.Random(seed).getrandbits(bits) == want:
                return seed, "sec_plus_counter", tried
    return None, "", tried


def _matches_per_token_anchored(want: int, base_sec: int,
                                expect_k: int, bits: int) -> bool:
    """以发现阶段的基准秒为锚点验证，计数器允许 ±3 抖动与模 1000 回绕。

    秒窗口覆盖基准秒前后 5 秒，兼容批量采集（时间戳相同）与实时采集两种情形。
    """
    for sec in range(base_sec - 5, base_sec + 6):
        for dk in range(-3, 4):
            k = expect_k % 1000
            seed = sec * 1000 + ((k + dk) % 1000)
            if random.Random(seed).getrandbits(bits) == want:
                return True
    return False


def _matches_per_token(want: int, ts: float, base_sec: int,
                       expect_k: int, bits: int, k_modulus: int = 1000) -> bool:
    """验证种子 sec*1000 + k；秒与计数器都在期望值附近小范围搜索。

    计数器在期望偏移 ±3 内、并按 k_modulus 回绕，容忍模回绕与少量抖动。
    """
    sec_collect = int(ts)
    lo = min(base_sec, sec_collect) - 2
    hi = max(base_sec, sec_collect) + 2
    for sec in range(lo, hi + 1):
        for dk in range(-3, 4):
            k = (expect_k + dk) % k_modulus
            seed = sec * 1000 + k
            if random.Random(seed).getrandbits(bits) == want:
                return True
    return False


def _matches_plain_ts(want: int, ts: float, bits: int, millis: bool) -> bool:
    sec_i = int(ts)
    for delta in range(-2, 3):
        sec = sec_i + delta
        seed = sec * 1000 if millis else sec
        if random.Random(seed).getrandbits(bits) == want:
            return True
    return False


def _mt_verify(
    seed: int, kind: str, values: list[int], bits: int, tried: int
) -> MTResult:
    rng = random.Random(seed)
    generated = [rng.getrandbits(bits) for _ in values]
    acc = sum(1 for a, b in zip(generated, values) if a == b) / len(values)
    return MTResult(acc >= 0.9, seed, kind, acc, tried)


# ---------------------------------------------------------------------------
# 哈希计数器假设
# ---------------------------------------------------------------------------

_HASHES = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
}


@dataclass
class HashCounterResult:
    matched: bool
    algorithm: str
    start_counter: int
    encoding: str
    heldout_accuracy: float


def test_hash_counter(samples: SampleSet, search_window: int = 10_000) -> HashCounterResult:
    """检验令牌是否为 hash(递增计数器) 的摘要，不依赖计数器的绝对起始值。

    思路：若 token_i = H(c+i)，则在给定 c 的候选下，后续令牌应逐一匹配。
    用前两个令牌在候选计数器窗口内定位 c，再用全部样本验证，避免假设
    “计数器从 0 开始”这一真实系统通常不成立的条件。
    """
    if samples.encoding not in ("hex", "base64url", "base64"):
        return HashCounterResult(False, "", 0, "", 0.0)
    from .tokens import decode_token

    targets = [decode_token(t, samples.encoding) for t in samples.tokens]
    if any(b is None for b in targets) or len(targets) < 4:
        return HashCounterResult(False, "", 0, "", 0.0)

    # 计数器的常见编码形式
    def inputs(c: int):
        return {
            "decimal": str(c).encode(),
            "hex": format(c, "x").encode(),
            "zero6": f"{c:06d}".encode(),
        }

    check_n = min(len(targets), 20)
    for algo, factory in _HASHES.items():
        # 用第一个令牌在窗口内找候选 c（同时尝试不同编码）
        for c0 in range(search_window):
            for enc_name, raw in inputs(c0).items():
                if factory(raw).digest() != targets[0]:
                    continue
                # 命中首令牌后，验证后续令牌是否为连续计数器
                ok = all(
                    factory(inputs(c0 + i)[enc_name]).digest() == targets[i]
                    for i in range(1, check_n)
                )
                if ok:
                    # 全量留出验证
                    full = all(
                        factory(inputs(c0 + i)[enc_name]).digest() == targets[i]
                        for i in range(check_n, len(targets))
                    )
                    acc = (check_n + (len(targets) - check_n if full else 0)) / len(targets)
                    return HashCounterResult(True, algo, c0, samples.encoding, acc)
    return HashCounterResult(False, "", 0, "", 0.0)


# ---------------------------------------------------------------------------
# 明文计数器 / 时间戳
# ---------------------------------------------------------------------------


@dataclass
class CounterResult:
    is_counter: bool
    delta: Optional[int]
    monotonic_ratio: float
    heldout_accuracy: float


def test_plain_counter(samples: SampleSet) -> CounterResult:
    if samples.int_values is None or samples.n < 4:
        return CounterResult(False, None, 0.0, 0.0)
    v = samples.int_values
    deltas = [v[i + 1] - v[i] for i in range(len(v) - 1)]
    monotonic = sum(1 for d in deltas if d > 0) / len(deltas)
    positive = [d for d in deltas if d > 0]
    if not positive or monotonic < 0.9:
        return CounterResult(False, None, monotonic, 0.0)
    mode_delta, mode_count = Counter(positive).most_common(1)[0]
    if mode_count / len(positive) < 0.8:
        return CounterResult(False, None, monotonic, 0.0)
    # 用恒定步长预测留出段：从 v[cut-1] 出发，目标 v[cut+i] 对应 (i+1) 个步长，
    # 即基准应为留出段首项的前一项，预测式与目标下标严格对齐
    cut = int(len(v) * 0.75)
    base = v[cut - 1]
    preds = [base + mode_delta * (i + 1) for i in range(len(v) - cut)]
    targets = v[cut:]
    acc = sum(1 for p, t in zip(preds, targets) if p == t) / max(1, len(targets))
    return CounterResult(acc >= 0.9, mode_delta, monotonic, acc)


@dataclass
class TimestampEmbedResult:
    found: bool
    unit: str
    positions: list[int]
    detail: str


def test_embedded_timestamp(samples: SampleSet) -> TimestampEmbedResult:
    """在令牌整数/十六进制中扫描与采集时间吻合的时间戳字段。"""
    if not samples.timestamps or samples.int_values is None:
        return TimestampEmbedResult(False, "", [], "")
    units = [
        # (单位名, 换算到秒的倍率, 允许的绝对误差，单位与该单位相同)
        ("秒", 1.0, 3.0),
        ("毫秒", 1_000.0, 2_000.0),
        ("微秒", 1_000_000.0, 50_000.0),
    ]
    hits: dict[str, list[int]] = defaultdict(list)
    for idx, (val, ts) in enumerate(zip(samples.int_values, samples.timestamps)):
        if val is None:
            continue
        for name, scale, tol in units:
            target = ts * scale
            if abs(val - target) <= tol:
                hits[name].append(idx)
                continue
            # 时间戳可能位于低 32/40/48 位
            for width in (32, 40, 48):
                low = val & ((1 << width) - 1)
                if abs(low - target) <= tol:
                    hits[name].append(idx)
                    break
    for name, idxs in hits.items():
        if len(idxs) >= max(2, samples.n * 0.5):
            return TimestampEmbedResult(
                True, name, idxs[:10], f"{len(idxs)}/{samples.n} 个令牌内嵌{name}级时间戳"
            )
    return TimestampEmbedResult(False, "", [], "")


# ---------------------------------------------------------------------------
# 猜测空间
# ---------------------------------------------------------------------------


@dataclass
class Guesswork:
    positional_min_entropy_bits: float
    positional_shannon_bits: float
    effective_bits: float
    alphabet_size: int
    variable_positions: int
    human: str
    reduction_reasons: list[str]


def estimate_guesswork(
    samples: SampleSet,
    prediction_penalty_bits: float = 0.0,
    prediction_reason: str = "",
) -> Guesswork:
    """逐位置最小熵求和作为保守有效熵，再施加预测器折减。"""
    reasons: list[str] = []
    pos_hmin = pos_h = 0.0
    variable = 0
    for pos in range(samples.min_length):
        col = samples.positional[pos]
        hmin = stats.min_entropy(col)
        h = stats.shannon_entropy(col)
        if hmin > 0.05:  # 几乎恒定的位置不计入可变位置
            variable += 1
        pos_hmin += hmin
        pos_h += h
    effective = max(0.0, pos_hmin - prediction_penalty_bits)
    if prediction_penalty_bits > 0 and prediction_reason:
        reasons.append(prediction_reason)
    if variable < samples.min_length:
        reasons.append(
            f"{samples.min_length - variable} 个位置字符恒定，不贡献随机性"
        )
    return Guesswork(
        pos_hmin,
        pos_h,
        effective,
        len(samples.alphabet),
        variable,
        humanize_guesswork(effective),
        reasons,
    )


def humanize_guesswork(bits: float) -> str:
    """把 2^bits 次猜测换算成不同攻击速率下的耗时描述。"""
    if bits <= 0:
        return "无需猜测（可直接计算）"
    rates = {"在线 10 次/秒": 10.0, "在线 1000 次/秒": 1_000.0, "离线 1e6 次/秒": 1e6}
    parts = []
    for name, rate in rates.items():
        seconds = (2**bits) / rate
        parts.append(f"{name}：{humanize_seconds(seconds)}")
    return "；".join(parts)


def humanize_seconds(sec: float) -> str:
    if sec < 60:
        return f"{sec:.1f} 秒"
    units = [
        (60.0, "分钟"),
        (60.0, "小时"),
        (24.0, "天"),
        (365.25, "年"),
    ]
    value = sec
    last = "秒"
    for factor, name in units:
        if value < factor:
            break
        value /= factor
        last = name
    if last == "年" and value > 1e12:
        return "超过万亿年"
    return f"{value:,.1f} {last}"
