"""令牌采集：从 HTTP 接口批量拉取，或从本地文件导入。

仅依赖标准库 urllib，支持：
  - URL 模板 {n} 分页参数、自定义请求头、请求间隔、超时、重试
  - JSON / JSONL / 纯文本 / CSV 响应解析，用点路径或正则提取令牌字段
  - 本地文件导入（.txt/.json/.jsonl/.csv），导入路径作为参数传入，不依赖工作目录
"""

from __future__ import annotations

import csv
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from .tokens import SampleSet, normalize_token


@dataclass
class CollectConfig:
    url: str
    count: int = 200
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    # 提取方式：json 点路径（如 data.token）、正则、或 null 表示整行即令牌
    json_path: Optional[str] = None
    regex: Optional[str] = None
    delay_ms: int = 0
    timeout: float = 10.0
    retries: int = 2
    page_param: Optional[str] = None  # 如 "page"，会以 {n} 形式注入 URL 模板
    insecure: bool = False


def collect_http(cfg: CollectConfig) -> SampleSet:
    tokens: list[str] = []
    timestamps: list[float] = []
    pattern = re.compile(cfg.regex) if cfg.regex else None
    data = cfg.body.encode() if cfg.body else None
    for i in range(cfg.count):
        url = cfg.url
        if cfg.page_param and "{n}" in url:
            url = url.format(n=i)
        req = urllib.request.Request(url, data=data, method=cfg.method,
                                     headers=cfg.headers)
        text = _http_request(req, cfg)
        found = _extract(text, cfg.json_path, pattern)
        if not found:
            raise ValueError(f"第 {i + 1} 次请求未提取到令牌（URL={url}），"
                             "请检查 --json-path/--regex 配置")
        # 一次请求可能返回多个令牌
        for tok in found:
            tokens.append(tok)
            timestamps.append(time.time())
        if len(tokens) >= cfg.count:
            break
        if cfg.delay_ms:
            time.sleep(cfg.delay_ms / 1000.0)
    tokens = tokens[: cfg.count]
    timestamps = timestamps[: cfg.count]
    return SampleSet(tokens, timestamps, source=cfg.url, label=_short_url(cfg.url))


def _http_request(req, cfg: CollectConfig) -> str:
    last_err: Optional[Exception] = None
    for attempt in range(cfg.retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=cfg.timeout) as resp:
                charset = resp.headers.get_content_charset() or "utf-8"
                return resp.read().decode(charset, errors="replace")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_err = exc
            if attempt < cfg.retries:
                time.sleep(0.5 * (attempt + 1))
    raise RuntimeError(f"请求失败（已重试 {cfg.retries} 次）：{last_err}")


def _extract(text: str, json_path: Optional[str],
             pattern: Optional[re.Pattern]) -> list[str]:
    if pattern is not None:
        return [m.group(1) if m.groups() else m.group(0)
                for m in pattern.finditer(text)]
    parsed = _try_json(text)
    if parsed is not None and json_path:
        values = _walk_json_path(parsed, json_path)
        return [str(v) for v in values if v is not None]
    if parsed is not None:
        # 自动找一个看起来像令牌的字符串字段
        found = _autofind_token(parsed)
        if found:
            return [found]
    # 退化为按行分割的纯文本
    return [line.strip() for line in text.splitlines() if line.strip()]


def _try_json(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _walk_json_path(obj, path: str) -> list:
    """支持 a.b.c 与数组下标的简单点路径；任一层级为列表则展开。"""
    current = [obj]
    for part in path.split("."):
        nxt = []
        for node in current:
            if isinstance(node, list):
                for item in node:
                    if isinstance(item, dict) and part in item:
                        nxt.append(item[part])
            elif isinstance(node, dict) and part in node:
                nxt.append(node[part])
        current = nxt
    out = []
    for v in current:
        if isinstance(v, list):
            out.extend(v)
        else:
            out.append(v)
    return out


def _autofind_token(obj, depth: int = 0) -> Optional[str]:
    if depth > 6:
        return None
    if isinstance(obj, str) and 16 <= len(obj) <= 256:
        return obj
    if isinstance(obj, dict):
        for key in ("token", "reset_token", "session", "session_id", "id", "value"):
            if key in obj and isinstance(obj[key], str):
                return obj[key]
        for v in obj.values():
            got = _autofind_token(v, depth + 1)
            if got:
                return got
    if isinstance(obj, list) and obj:
        return _autofind_token(obj[0], depth + 1)
    return None


def import_file(path: str, json_path: Optional[str] = None,
                regex: Optional[str] = None,
                column: Optional[str] = None) -> SampleSet:
    """从本地文件导入令牌。文件格式按扩展名识别。"""
    if path.lower().endswith((".json", ".jsonl")):
        tokens, timestamps = _import_json(path, json_path)
    elif path.lower().endswith(".csv"):
        tokens, timestamps = _import_csv(path, column)
    else:
        tokens, timestamps = _import_text(path, regex)
    if not tokens:
        raise ValueError(f"未能从 {path} 导入任何令牌")
    return SampleSet(tokens, timestamps, source=f"file://{path}", label=path.split("/")[-1])


def _import_text(path: str, regex: Optional[str]) -> tuple[list[str], list[float]]:
    pattern = re.compile(regex) if regex else None
    tokens, timestamps = [], []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if pattern:
                for m in pattern.finditer(line):
                    tokens.append(normalize_token(
                        m.group(1) if m.groups() else m.group(0)))
                    timestamps.append(time.time())
            else:
                # 支持 "token,timestamp" 或 "token<TAB>timestamp" 形式
                parts = re.split(r"[,\t]", line, maxsplit=1)
                tokens.append(normalize_token(parts[0]))
                timestamps.append(_parse_ts(parts[1]) if len(parts) > 1 else time.time())
    return tokens, timestamps


def _import_json(path: str, json_path: Optional[str]) -> tuple[list[str], list[float]]:
    with open(path, "r", encoding="utf-8") as fh:
        if path.lower().endswith(".jsonl"):
            docs = [json.loads(line) for line in fh if line.strip()]
        else:
            docs = json.load(fh)
    if isinstance(docs, dict):
        docs = [docs]
    if not isinstance(docs, list):
        raise ValueError("JSON 顶层应为对象或数组")
    tokens, timestamps = [], []
    for doc in docs:
        if isinstance(doc, str):
            tokens.append(doc)
            timestamps.append(time.time())
        elif isinstance(doc, dict):
            values = _walk_json_path(doc, json_path) if json_path else \
                [_autofind_token(doc)]
            for v in values:
                if v is not None:
                    tokens.append(str(v))
                    timestamps.append(_doc_timestamp(doc) or time.time())
    return tokens, timestamps


def _import_csv(path: str, column: Optional[str]) -> tuple[list[str], list[float]]:
    tokens, timestamps = [], []
    with open(path, "r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise ValueError("CSV 缺少表头")
        tok_col = column or next(
            (c for c in reader.fieldnames if "token" in c.lower() or c.lower() == "id"),
            reader.fieldnames[0],
        )
        ts_col = next((c for c in reader.fieldnames if "time" in c.lower() or
                       "date" in c.lower() or "ts" in c.lower()), None)
        for row in reader:
            val = row.get(tok_col, "").strip()
            if val:
                tokens.append(normalize_token(val))
                timestamps.append(_parse_ts(row[ts_col]) if ts_col and row.get(ts_col)
                                  else time.time())
    return tokens, timestamps


def _doc_timestamp(doc: dict) -> Optional[float]:
    for key in ("timestamp", "time", "ts", "created_at"):
        if key in doc:
            return _parse_ts(str(doc[key]))
    return None


def _parse_ts(value: str) -> float:
    value = value.strip()
    try:
        num = float(value)
        # 毫秒/微秒时间戳归一化
        if num > 1e14:
            return num / 1e6
        if num > 1e11:
            return num / 1e3
        return num
    except ValueError:
        pass
    try:
        return time.mktime(time.strptime(value[:19], "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        return time.time()


def _short_url(url: str) -> str:
    host = re.sub(r"^https?://", "", url).split("/")[0]
    return host or url
