"""命令行入口。

子命令：
  lab        启动本地靶场 HTTP 服务
  collect    从接口批量采集令牌，保存为 .jsonl（原始证据留档）
  import     从本地文件导入令牌并直接评估
  analyze    对采集结果/接口/文件执行评估，产出 HTML + JSON 报告
  demo       一键演示：启动内存靶场，对全部 7 个生成器评估并出对比报告
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from http.server import ThreadingHTTPServer

from . import __version__, lab_server
from .analyzer import analyze
from .collector import CollectConfig, collect_http, import_file
from .report import render_compare_html, render_html, render_json
from .tokens import SampleSet


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="token-rng-audit",
        description="令牌（重置链接/会话 ID）随机性评估工具 — 仅限授权测试使用")
    p.add_argument("--version", action="version", version=f"token-rng-audit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    lab = sub.add_parser("lab", help="启动本地靶场")
    lab.add_argument("--host", default="127.0.0.1")
    lab.add_argument("--port", type=int, default=lab_server.PORT_DEFAULT)

    col = sub.add_parser("collect", help="从 HTTP 接口采集令牌")
    col.add_argument("--url", required=True, help="支持 {n} 分页占位符")
    col.add_argument("--count", type=int, default=200)
    col.add_argument("--method", default="GET")
    col.add_argument("--header", action="append", default=[], help="Key: Value，可重复")
    col.add_argument("--body")
    col.add_argument("--json-path", help="JSON 点路径，如 data.token")
    col.add_argument("--regex", help="正则提取（首个分组）")
    col.add_argument("--page-param")
    col.add_argument("--delay-ms", type=int, default=0)
    col.add_argument("--timeout", type=float, default=10.0)
    col.add_argument("--out", required=True, help="输出 .jsonl 留档路径")

    imp = sub.add_parser("import", help="从本地文件导入并评估")
    _add_analyze_args(imp, need_out=True, with_extract=True)
    imp.add_argument("--file", required=True, help=".txt/.json/.jsonl/.csv")
    imp.add_argument("--column", help="CSV 令牌列名")

    ana = sub.add_parser("analyze", help="执行评估并生成报告")
    _add_analyze_args(ana, need_out=True, with_extract=True)
    src = ana.add_mutually_exclusive_group(required=True)
    src.add_argument("--url")
    src.add_argument("--file")
    src.add_argument("--samples", help="collect 子命令产出的 .jsonl")
    ana.add_argument("--count", type=int, default=200)
    ana.add_argument("--method", default="GET")
    ana.add_argument("--header", action="append", default=[])
    ana.add_argument("--body")
    ana.add_argument("--delay-ms", type=int, default=0)
    ana.add_argument("--timeout", type=float, default=10.0)
    ana.add_argument("--label")

    demo = sub.add_parser("demo", help="对靶场全部生成器一键评估")
    demo.add_argument("--count", type=int, default=300)
    demo.add_argument("--out-dir", default="reports")
    return p


def _add_analyze_args(parser: argparse.Namespace, need_out: bool,
                      with_extract: bool = False) -> None:
    parser.add_argument("--out", required=need_out,
                        help="HTML 报告输出路径（同时生成同名 .json）")
    if with_extract:
        parser.add_argument("--json-path")
        parser.add_argument("--regex")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "lab":
        lab_server.serve(args.host, args.port)
        return 0
    if args.cmd == "collect":
        return _cmd_collect(args)
    if args.cmd == "import":
        return _cmd_import(args)
    if args.cmd == "analyze":
        return _cmd_analyze(args)
    if args.cmd == "demo":
        return _cmd_demo(args)
    return 2


# ---------------------------------------------------------------------------
# 子命令实现
# ---------------------------------------------------------------------------


def _parse_headers(rows: list[str]) -> dict[str, str]:
    headers = {}
    for row in rows:
        if ":" not in row:
            raise SystemExit(f"--header 参数格式应为 Key: Value：{row}")
        k, v = row.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def _cmd_collect(args) -> int:
    cfg = CollectConfig(
        url=args.url, count=args.count, method=args.method,
        headers=_parse_headers(args.header), body=args.body,
        json_path=args.json_path, regex=args.regex,
        page_param=args.page_param, delay_ms=args.delay_ms,
        timeout=args.timeout)
    samples = collect_http(cfg)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        for tok, ts in zip(samples.tokens, samples.timestamps):
            fh.write(json.dumps({"token": tok, "timestamp": ts},
                                ensure_ascii=False) + "\n")
    print(f"[+] 已采集 {samples.n} 个令牌（唯一 {samples.unique_count}）→ {args.out}")
    return 0


def _cmd_import(args) -> int:
    samples = import_file(args.file, json_path=args.json_path,
                          regex=args.regex, column=getattr(args, "column", None))
    return _run_analysis(samples, args.out, label=samples.label)


def _cmd_analyze(args) -> int:
    if args.file:
        samples = import_file(args.file, json_path=args.json_path, regex=args.regex)
    elif args.samples:
        samples = import_file(args.samples, json_path="token")
    else:
        cfg = CollectConfig(
            url=args.url, count=args.count, method=args.method,
            headers=_parse_headers(args.header), body=args.body,
            json_path=args.json_path, regex=args.regex,
            delay_ms=args.delay_ms, timeout=args.timeout)
        samples = collect_http(cfg)
    if getattr(args, "label", None):
        samples.label = args.label
    return _run_analysis(samples, args.out, label=samples.label)


def _run_analysis(samples: SampleSet, out_path: str, label: str = "") -> int:
    print(f"[*] 评估样本集 {label or samples.label}：{samples.n} 个令牌，"
          f"编码={samples.encoding}，长度={samples.min_length}")
    result = analyze(samples)
    data = result.to_dict()
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(render_html(data))
    json_path = os.path.splitext(out_path)[0] + ".json"
    with open(json_path, "w", encoding="utf-8") as fh:
        fh.write(render_json(data))
    v = result.verdict
    print(f"[+] 总评：{v.grade} — {v.headline}")
    print(f"    有效熵 {v.guesswork_bits:.1f} bit；通过 {v.status_counts['pass']} / "
          f"警告 {v.status_counts['warn']} / 失败 {v.status_counts['fail']}")
    print(f"[+] 报告：{out_path}")
    print(f"[+] 机器可读结果：{json_path}")
    return 0 if v.status_counts["fail"] == 0 else 1


def _cmd_demo(args) -> int:
    """在后台线程启动真实 HTTP 靶场，通过真实采集链路评估全部生成器。"""
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), lab_server.LabHandler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)
    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)
    results = []
    try:
        for item in lab_server.generators.CATALOG:
            name = item["name"]
            lab_server.generators.reset_state()
            url = f"http://127.0.0.1:{port}/batch/{name}?n={args.count}"
            cfg = CollectConfig(url=url, count=args.count, json_path="tokens")
            samples = collect_http(cfg)
            samples.label = name
            result = analyze(samples)
            data = result.to_dict()
            results.append(data)
            page = os.path.join(out_dir, f"{name}.html")
            with open(page, "w", encoding="utf-8") as fh:
                fh.write(render_html(data))
            v = result.verdict
            print(f"[{'!' if v.status_counts['fail'] else ' '}] {name:14s} "
                  f"{v.grade_en:12s} 有效熵={v.guesswork_bits:7.1f}bit "
                  f"失败项={v.status_counts['fail']} → {page}")
        compare_path = os.path.join(out_dir, "comparison.html")
        with open(compare_path, "w", encoding="utf-8") as fh:
            fh.write(render_compare_html(results))
        with open(os.path.join(out_dir, "comparison.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(results, fh, ensure_ascii=False, indent=2)
        print(f"[+] 对比报告：{compare_path}")
    finally:
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
