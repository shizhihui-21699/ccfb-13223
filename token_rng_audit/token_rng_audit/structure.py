"""令牌结构指纹：UUID / JWT / 常见前缀等。"""

from __future__ import annotations

import re
from typing import Optional

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-([0-9a-fA-F])[0-9a-fA-F]{3}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_JWT_RE = re.compile(r"^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$")


def structural_fingerprint(tokens: list[str]) -> Optional[dict]:
    """识别整批令牌共有的结构特征。"""
    first = tokens[0]
    m = _UUID_RE.match(first)
    if m and all(_UUID_RE.match(t) for t in tokens):
        version = int(m.group(1), 16)
        note = {
            1: "UUIDv1 含 MAC 地址与 60 位时间戳，可推断生成时间与节点，不应用作不可预测令牌",
            4: "UUIDv4 随机字段占 122 位，结构本身安全，但仍需检验随机性",
        }.get(version, "非标准版本号")
        return {"type": "uuid", "version": version, "note": note}
    if _JWT_RE.match(first) and all(_JWT_RE.match(t) for t in tokens):
        return {
            "type": "jwt-like",
            "note": "形如 JWT 的三段式结构；JWT 是带签名的承载凭证，默认不加密，"
            "其随机性取决于内部 jti/随机字段，建议提取 payload 后单独评估",
        }
    # 公共前缀 / 公共后缀
    prefix = _common_prefix(tokens)
    suffix = _common_suffix(tokens)
    if len(prefix) >= 4 or len(suffix) >= 4:
        return {
            "type": "fixed-affix",
            "prefix": prefix,
            "suffix": suffix,
            "note": "存在固定前缀/后缀，有效随机空间只来自中间可变部分",
        }
    return None


def _common_prefix(tokens: list[str]) -> str:
    out = []
    for chars in zip(*tokens):
        if len(set(chars)) == 1:
            out.append(chars[0])
        else:
            break
    return "".join(out)


def _common_suffix(tokens: list[str]) -> str:
    return _common_prefix([t[::-1] for t in tokens])[::-1]
