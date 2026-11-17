"""令牌样本处理：归一化、解码、按位置展开。

一份 SampleSet 保存原始令牌及采集时间戳，并提供：
  - chars[i][pos]      每条令牌在 pos 位置的字符（等长部分）
  - byte_stream        解码后的字节（hex / base64url / base64 / 整数字节）
  - int_values         可整体解释为整数时的整数值
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Optional

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_\-]+$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+=*$")
_DEC_RE = re.compile(r"^\d+$")
_UUIDISH_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_JWTISH_RE = re.compile(r"^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$")


def normalize_token(raw: str) -> str:
    """去掉首尾空白与常见分隔，统一为待分析字符串。"""
    t = raw.strip()
    # 接受 “令牌: 前缀xxxx” 这类粘贴格式时不做激进处理，仅去空白
    return t


def detect_encoding(token: str) -> str:
    """猜测编码：hex / base64url / base64 / decimal / text。

    单令牌层面纯十六进制数字串与十进制无法区分（如 "17748702" 两者都合法），
    这里对纯数字默认 decimal；批次层面的歧义由 SampleSet._consensus_encoding
    结合整批令牌（是否含 a-f、长度是否一致）裁决。
    """
    t = token
    if _DEC_RE.match(t):
        return "decimal"
    if len(t) % 2 == 0 and _HEX_RE.match(t):
        return "hex"  # 含 a-f/A-F 的十六进制（纯数字已在上面分支返回 decimal）
    if _B64URL_RE.match(t) and ("-" in t or "_" in t or len(t) % 4 != 0):
        return "base64url"
    if _B64_RE.match(t):
        return "base64"
    if _B64URL_RE.match(t):
        return "base64url"
    return "text"


def _has_alpha(t: str) -> bool:
    return any(c.isalpha() for c in t)


def decode_token(token: str, encoding: Optional[str] = None) -> Optional[bytes]:
    """把令牌解码为字节；无法可靠解码时返回 None。"""
    enc = encoding or detect_encoding(token)
    try:
        if enc == "hex":
            return bytes.fromhex(token)
        if enc == "decimal":
            return int(token).to_bytes((int(token).bit_length() + 7) // 8 or 1, "big")
        if enc == "base64url":
            pad = "=" * (-len(token) % 4)
            return base64.urlsafe_b64decode(token + pad)
        if enc == "base64":
            return base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
    except (ValueError, binascii.Error):
        return None
    return None


def token_to_int(token: str) -> Optional[int]:
    """尝试把令牌整体解释为大整数（hex/decimal，或解码字节按大端）。

    含结构分隔的令牌（UUID、JWT 等）不做整体数值化——它们应按字段分析，
    强行解码成大整数会让 LCG/相关性类检验产生无意义的组合爆炸。
    """
    if _UUIDISH_RE.match(token) or _JWTISH_RE.match(token):
        return None
    enc = detect_encoding(token)
    try:
        if enc == "hex":
            return int(token, 16)
        if enc == "decimal":
            return int(token)
    except ValueError:
        return None
    raw = decode_token(token, enc)
    if raw is not None and len(raw) <= 8:  # 仅对 ≤64 bit 的解码值做整数分析
        return int.from_bytes(raw, "big")
    return None


@dataclass
class SampleSet:
    """一批待评估令牌。"""

    tokens: list[str]
    timestamps: list[float] = field(default_factory=list)
    source: str = "unknown"
    encoding: str = "auto"
    label: str = ""

    def __post_init__(self) -> None:
        self.tokens = [normalize_token(t) for t in self.tokens if t and t.strip()]
        if not self.tokens:
            raise ValueError("样本为空：没有可分析的令牌")
        if self.encoding == "auto":
            self.encoding = self._consensus_encoding()
        self.lengths = [len(t) for t in self.tokens]
        self.min_length = min(self.lengths)
        self.max_length = max(self.lengths)
        self.unique_count = len(set(self.tokens))
        self.duplicate_count = len(self.tokens) - self.unique_count
        self.alphabet = sorted({ch for t in self.tokens for ch in t})
        # 按位置取字符（只取所有令牌都覆盖到的前 min_length 个位置）
        self.positional = [
            [self.tokens[i][p] for i in range(len(self.tokens))]
            for p in range(self.min_length)
        ]
        # 字节解码（逐个尝试，失败的跳过）
        decoded = [b for t in self.tokens if (b := decode_token(t, self.encoding))]
        self.decoded_bytes: list[bytes] = decoded
        if decoded:
            self.byte_stream = bytes(x for b in decoded for x in b)
            min_blen = min(len(b) for b in decoded)
            self.byte_positions = [
                [decoded[i][p] for i in range(len(decoded))] for p in range(min_blen)
            ]
        else:
            self.byte_stream = b""
            self.byte_positions = []
        # 整数值（仅当全部可解释时保留，保证按序号对齐）。
        # 用批次裁决后的编码解析，避免纯数字 hex 令牌被逐令牌误判为十进制。
        ints = [self._token_int_with_encoding(t) for t in self.tokens]
        self.int_values: Optional[list[int]] = (
            ints if all(v is not None for v in ints) else None
        )

    def _consensus_encoding(self) -> str:
        """批次级编码裁决，解决纯数字令牌的 hex/decimal 歧义。

        规则：
          - 若整批等长、偶长度、全部落在十六进制字符集，且有相当比例含
            a-f/A-F 字母，则判为 hex（典型的 LCG/MT 十六进制输出）；
          - 否则回退到逐令牌多数投票，纯数字串计为 decimal。
        """
        toks = self.tokens
        fixed_even = (
            len(toks[0]) % 2 == 0 and all(len(t) == len(toks[0]) for t in toks)
        )
        all_hexish = all(_HEX_RE.match(t) for t in toks)
        if fixed_even and all_hexish:
            alpha_ratio = sum(1 for t in toks if _has_alpha(t)) / len(toks)
            # 含字母的比例足以证明这是十六进制数据而非十进制计数器
            if alpha_ratio >= 0.2:
                return "hex"
        votes: dict[str, int] = {}
        for t in toks:
            enc = detect_encoding(t)
            votes[enc] = votes.get(enc, 0) + 1
        return max(votes, key=votes.get)

    def _token_int_with_encoding(self, token: str) -> Optional[int]:
        """按批次裁决编码把令牌转为整数。"""
        if _UUIDISH_RE.match(token) or _JWTISH_RE.match(token):
            return None
        try:
            if self.encoding == "hex" and _HEX_RE.match(token):
                return int(token, 16)
            if self.encoding == "decimal" and _DEC_RE.match(token):
                return int(token)
        except ValueError:
            return None
        raw = decode_token(token, self.encoding)
        if raw is not None and len(raw) <= 8:
            return int.from_bytes(raw, "big")
        return None

    @property
    def n(self) -> int:
        return len(self.tokens)

    @property
    def is_fixed_length(self) -> bool:
        return self.min_length == self.max_length

    def all_chars(self) -> list[str]:
        return [ch for t in self.tokens for ch in t]
