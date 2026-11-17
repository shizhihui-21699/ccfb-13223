"""单元测试：统计原语 + 各缺陷检测路径。

仅用标准库 unittest，运行：python3 -m unittest discover -s tests -v
"""

import math
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from token_rng_audit import generators
from token_rng_audit import stats
from token_rng_audit.analyzer import analyze
from token_rng_audit.predict import (
    estimate_guesswork,
    markov_prediction,
    recover_lcg,
    recover_mt19937,
    test_hash_counter,
    test_plain_counter,
)
from token_rng_audit.tokens import (
    SampleSet,
    decode_token,
    detect_encoding,
    token_to_int,
)
import time


def make_samples(name, n=200, with_ts=True):
    g = generators.get(name)
    generators.reset_state()
    toks = [g() for _ in range(n)]
    ts = [time.time() + i * 0.0005 for i in range(n)] if with_ts else []
    return SampleSet(toks, ts, source="test", label=name)


class TestStats(unittest.TestCase):
    def test_uniform_entropy(self):
        # 4 个等概率符号，熵应为 2 bit
        self.assertAlmostEqual(stats.shannon_entropy([0, 1, 2, 3] * 25), 2.0, places=6)

    def test_min_entropy(self):
        # 最可能符号 'a' 占 3/4，最小熵 = -log2(0.75)
        self.assertAlmostEqual(
            stats.min_entropy(["a", "a", "a", "b"]), -math.log2(0.75), places=6)

    def test_chi2_uniform_high_p(self):
        obs = [100] * 10
        _, _, p = stats.chi_square_uniform(obs)
        self.assertGreater(p, 0.5)

    def test_chi2_skewed_low_p(self):
        obs = [950] + [5] * 10 + [0] * 5
        _, _, p = stats.chi_square_uniform(obs)
        self.assertLess(p, 0.001)

    def test_spearman_monotonic(self):
        x = list(range(50))
        self.assertAlmostEqual(stats.spearman(x, [v * 3 + 1 for v in x]), 1.0, places=6)

    def test_cramers_v_independent_near_zero(self):
        # 大样本均匀列联表，修正后的 V 应接近 0
        table = [[100] * 8 for _ in range(8)]
        self.assertLess(stats.cramers_v(table), 0.05)

    def test_cramers_v_perfect_one(self):
        # 完美一一对应，V=1
        table = [[1 if i == j else 0 for j in range(5)] for i in range(5)]
        for i in range(5):
            table[i][i] = 50
        self.assertAlmostEqual(stats.cramers_v(table), 1.0, places=6)

    def test_runs_test_constant(self):
        z, p = stats.runs_test([1] * 30)
        self.assertEqual(p, 0.0)


class TestTokens(unittest.TestCase):
    def test_encoding_detection(self):
        self.assertEqual(detect_encoding("48656c6c6f"), "hex")  # 含字母 → hex
        self.assertEqual(detect_encoding("1234567890"), "decimal")  # 纯数字 → decimal
        self.assertEqual(detect_encoding("100080"), "decimal")  # 偶长度纯数字不判 hex
        self.assertTrue(detect_encoding("aBc9-_xZ") in ("base64url", "base64"))

    def test_decode_hex_base64(self):
        self.assertEqual(decode_token("414243", "hex"), b"ABC")
        self.assertIsNone(decode_token("zzz-not-valid", "hex"))

    def test_uuid_not_numeric(self):
        import uuid
        self.assertIsNone(token_to_int(str(uuid.uuid1())))
        self.assertIsNone(token_to_int(str(uuid.uuid4())))

    def test_hex_to_int(self):
        self.assertEqual(token_to_int("ff"), 255)
        self.assertEqual(token_to_int("123"), 123)


class TestPredictors(unittest.TestCase):
    def test_lcg_recovery_exact_params(self):
        samples = make_samples("lcg", n=120)
        result = recover_lcg(samples.int_values)
        self.assertTrue(result.recovered)
        self.assertEqual(result.modulus, 2**32)
        self.assertEqual(result.multiplier, generators._LCG_A)
        self.assertEqual(result.increment, generators._LCG_C)
        self.assertGreaterEqual(result.heldout_accuracy, 0.9)

    def test_lcg_skips_wide_ints(self):
        wide = [1 << 100 | i for i in range(20)]
        result = recover_lcg(wide)
        self.assertFalse(result.recovered)

    def test_mt_seed_recovery(self):
        samples = make_samples("mt_time_seed", n=120)
        result = recover_mt19937(samples)
        self.assertTrue(result.recovered)
        self.assertGreaterEqual(result.heldout_accuracy, 0.8)

    def test_hash_counter_detection_offset(self):
        # 大起始计数器也应识别，不依赖从 0 开始
        generators.reset_state()
        generators._counter_state["hash"] = 7777
        toks = [generators.gen_hash_counter() for _ in range(100)]
        result = test_hash_counter(SampleSet(toks, source="t"))
        self.assertTrue(result.matched)
        self.assertEqual(result.algorithm, "sha256")

    def test_plain_counter(self):
        samples = make_samples("counter", n=80)
        result = test_plain_counter(samples)
        self.assertTrue(result.is_counter)
        self.assertEqual(result.delta, 1)

    def test_markov_secure_not_predictable(self):
        samples = make_samples("secure", n=200)
        result = markov_prediction(samples)
        self.assertFalse(result.predictable)

    def test_guesswork_secure_vs_weak(self):
        secure = make_samples("secure", n=200)
        weak = make_samples("counter", n=80)
        g_secure = estimate_guesswork(secure)
        g_weak = estimate_guesswork(weak)
        self.assertGreater(g_secure.effective_bits, 128)
        self.assertLess(g_weak.effective_bits, 32)


class TestEndToEndGrading(unittest.TestCase):
    def test_secure_is_strong(self):
        result = analyze(make_samples("secure", n=250))
        self.assertEqual(result.verdict.grade_en, "STRONG")
        self.assertFalse(result.verdict.prediction_feasible)
        self.assertGreaterEqual(result.verdict.guesswork_bits, 128)

    def test_each_vulnerable_generator_predictable(self):
        for name in ("counter", "hash_counter", "timestamp",
                     "lcg", "mt_time_seed", "uuid_v1"):
            with self.subTest(generator=name):
                result = analyze(make_samples(name, n=200))
                # 缺陷生成器的总评必须落入 WEAK/PREDICTABLE，且有效熵低于安全线
                self.assertIn(
                    result.verdict.grade_en, ("WEAK", "PREDICTABLE"),
                    msg=f"{name} 应判定为弱/可预测，实际 {result.verdict.grade_en}")
                self.assertLess(result.verdict.guesswork_bits, 128)

    def test_small_sample_warns(self):
        result = analyze(make_samples("secure", n=15))
        self.assertTrue(any("样本" in w for w in result.warnings))

    def test_duplicates_flagged(self):
        toks = ["abcd1234efgh5678"] * 40 + [f"{i:016x}" for i in range(40)]
        result = analyze(SampleSet(toks, source="t"))
        dup = next(f for f in result.findings if f.check_id == "duplicates")
        self.assertEqual(dup.status.value, "fail")


class TestGuessworkHumanization(unittest.TestCase):
    def test_humanize_zero(self):
        from token_rng_audit.predict import humanize_guesswork
        self.assertIn("无需猜测", humanize_guesswork(0))

    def test_humanize_large(self):
        from token_rng_audit.predict import humanize_guesswork
        text = humanize_guesswork(256)
        self.assertIn("年", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
