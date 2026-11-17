"""靶场令牌生成器：1 个安全基线 + 6 个有缺陷实现。

每个生成器是无参可调用对象，返回字符串令牌。
计数器类生成器的内部状态用锁保护，保证线程安全。
"""

from __future__ import annotations

import hashlib
import random
import secrets
import threading
import time
import uuid

# 刻意选取的“教科书式”LCG 参数（32 位模数，输出十六进制字符串）
_LCG_M = 2**32
_LCG_A = 1103515245
_LCG_C = 12345

_lock = threading.Lock()
_counter_state = {"plain": 100000, "hash": 1, "mt": 0}
_lcg_state = {"x": int(time.time()) % _LCG_M}
_mt_rng = random.Random(int(time.time()))  # 进程启动时以秒级时间戳播种一次


def gen_secure() -> str:
    """安全基线：secrets.token_urlsafe 内部为 os.urandom（CSPRNG）。"""
    return secrets.token_urlsafe(32)


def gen_counter() -> str:
    """缺陷 1：明文自增 ID，可枚举其他用户令牌。"""
    with _lock:
        _counter_state["plain"] += 1
        return str(_counter_state["plain"])


def gen_timestamp() -> str:
    """缺陷 2：时间戳 + 仅 16 bit 随机后缀，熵集中在极小空间。"""
    return f"{int(time.time())}{secrets.randbelow(1 << 16):05d}"


def gen_lcg() -> str:
    """缺陷 3：线性同余生成器，参数可由少量输出恢复。"""
    with _lock:
        _lcg_state["x"] = (_LCG_A * _lcg_state["x"] + _LCG_C) % _LCG_M
        return f"{_lcg_state['x']:08x}"


def gen_mt_time_seed() -> str:
    """缺陷 4：MT19937 + 可猜弱种子（秒级时间戳拼接小计数器）。

    种子空间 = 时间窗口 × 小计数器，攻击者可在小窗口内暴力恢复并复现随机流。
    """
    with _lock:
        seq = _counter_state["mt"]
        _counter_state["mt"] += 1
    seed = int(time.time()) * 1000 + (seq % 1000)
    rng = random.Random(seed)
    return f"{rng.getrandbits(64):016x}"


def gen_hash_counter() -> str:
    """缺陷 5：sha256(计数器)，哈希不提供不可预测性。"""
    with _lock:
        n = _counter_state["hash"]
        _counter_state["hash"] += 1
    return hashlib.sha256(str(n).encode()).hexdigest()


def gen_uuid_v1() -> str:
    """缺陷 6：UUIDv1，含节点 MAC 与 60 位时间戳，随机成分仅 clock_seq。"""
    return str(uuid.uuid1())


_GENERATORS = {
    "secure": gen_secure,
    "counter": gen_counter,
    "hash_counter": gen_hash_counter,
    "timestamp": gen_timestamp,
    "lcg": gen_lcg,
    "mt_time_seed": gen_mt_time_seed,
    "uuid_v1": gen_uuid_v1,
}

CATALOG = [
    {"name": "secure", "safe": True,
     "description": "secrets.token_urlsafe(32)，CSPRNG 安全基线"},
    {"name": "counter", "safe": False,
     "description": "明文递增计数器，可直接枚举劫持"},
    {"name": "hash_counter", "safe": False,
     "description": "sha256(递增计数器)，哈希不增加不可预测性"},
    {"name": "timestamp", "safe": False,
     "description": "秒级时间戳 + 16bit 随机后缀，有效熵极低"},
    {"name": "lcg", "safe": False,
     "description": "线性同余生成器，参数可从输出序列恢复"},
    {"name": "mt_time_seed", "safe": False,
     "description": "MT19937 以秒级时间戳播种，种子可暴力恢复"},
    {"name": "uuid_v1", "safe": False,
     "description": "UUIDv1 暴露 MAC 与时间戳，随机位仅 14 bit"},
]


def get(name: str):
    return _GENERATORS.get(name)


def reset_state() -> None:
    """重置全部有状态生成器（靶场冷启动 / 每轮独立演示用）。"""
    with _lock:
        _counter_state["plain"] = 100000
        _counter_state["hash"] = 1
        _counter_state["mt"] = 0
        _lcg_state["x"] = int(time.time()) % _LCG_M
