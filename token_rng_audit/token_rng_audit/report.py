"""单文件 HTML 报告生成：内联 CSS/SVG，无外部依赖，可离线分发。"""

from __future__ import annotations

import html
import json
from typing import Any

from .findings import Status

_STATUS_LABEL = {
    Status.PASS: "通过",
    Status.WARN: "警告",
    Status.FAIL: "失败",
    Status.INFO: "信息",
}

_GRADE_STYLE = {
    "STRONG": ("strong", "强"),
    "MODERATE": ("moderate", "中等"),
    "WEAK": ("weak", "弱"),
    "PREDICTABLE": ("predictable", "可预测"),
}


def render_html(result: dict[str, Any]) -> str:
    sample = result["sample"]
    verdict = result["verdict"]
    grade_cls, grade_text = _GRADE_STYLE.get(
        verdict["grade_en"], ("weak", verdict["grade"]))
    parts = [_HTML_HEAD, "<body>", _top_band(result, grade_cls, grade_text)]
    parts.append(_summary_cards(result))
    if result.get("warnings"):
        parts.append(_warnings(result["warnings"]))
    parts.append(_findings_section(result["findings"]))
    parts.append(_guesswork_section(result["guesswork"]))
    parts.append(_charts_section(result["findings"]))
    parts.append(_sample_section(sample))
    parts.append(_methodology_footer())
    parts.append("</body></html>")
    return "".join(parts)


def render_compare_html(results: list[dict[str, Any]]) -> str:
    """多个生成器横向对比报告（demo/批量评估用）。"""
    rows = []
    for r in results:
        v = r["verdict"]
        rows.append(
            "<tr>"
            f"<td>{html.escape(r['sample']['label'])}</td>"
            f"<td><span class='pill pill-{_GRADE_STYLE.get(v['grade_en'], ('weak',''))[0]}'>"
            f"{html.escape(v['grade'])}</span></td>"
            f"<td>{v['guesswork_bits']:.1f}</td>"
            f"<td class='num'>{v['status_counts']['pass']}</td>"
            f"<td class='num warn-txt'>{v['status_counts']['warn']}</td>"
            f"<td class='num fail-txt'>{v['status_counts']['fail']}</td>"
            f"<td>{'是' if v['prediction_feasible'] else '否'}</td>"
            "</tr>"
        )
    body = f"""
<div class="wrap">
  <h1>令牌随机性批量评估对比</h1>
  <p class="sub">共评估 {len(results)} 个生成器 / 样本集，点击各单项报告查看细节。</p>
  <table class="compare">
    <thead><tr><th>样本集</th><th>总评</th><th>有效熵(bit)</th>
    <th>通过</th><th>警告</th><th>失败</th><th>可预测</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  <h2>结论摘要</h2><ul class="verdict-list">
"""
    items = []
    for r in results:
        items.append(
            f"<li><b>{html.escape(r['sample']['label'])}</b>："
            f"{html.escape(r['verdict']['headline'])}</li>")
    body += "".join(items) + "</ul>"
    body += _methodology_footer() + "</div>"
    return _HTML_HEAD + "<body>" + body + "</body></html>"


# ---------------------------------------------------------------------------
# 页面区块
# ---------------------------------------------------------------------------


def _top_band(result: dict, grade_cls: str, grade_text: str) -> str:
    v = result["verdict"]
    s = result["sample"]
    return f"""
<header class="hero hero-{grade_cls}">
  <div class="wrap">
    <div class="grade">{html.escape(grade_text)}</div>
    <h1>{html.escape(s['label'])} — 令牌随机性评估报告</h1>
    <p class="headline">{html.escape(v['headline'])}</p>
    <p class="explain">{html.escape(v['explanation'])}</p>
  </div>
</header>"""


def _summary_cards(result: dict) -> str:
    s = result["sample"]
    v = result["verdict"]
    g = result["guesswork"]
    cards = [
        ("样本数量", f"{s['count']}（唯一 {s['unique']}）"),
        ("编码识别", s["encoding"]),
        ("令牌长度", f"{s['min_length']}" if s["fixed_length"]
         else f"{s['min_length']}–{s['max_length']}"),
        ("字母表规模", f"{s['alphabet_size']} 个字符"),
        ("有效熵", f"{g['effective_bits']:.1f} bit"),
        ("可预测", "是（高风险）" if v["prediction_feasible"] else "未证实"),
    ]
    items = "".join(
        f"<div class='card'><div class='card-k'>{html.escape(k)}</div>"
        f"<div class='card-v'>{html.escape(str(val))}</div></div>"
        for k, val in cards)
    return f"<div class='wrap'><div class='cards'>{items}</div></div>"


def _warnings(warnings: list[str]) -> str:
    items = "".join(f"<li>{html.escape(w)}</li>" for w in warnings)
    return f"<div class='wrap'><div class='warnbox'><b>样本可靠性提示</b><ul>{items}</ul></div></div>"


def _findings_section(findings: list[dict]) -> str:
    blocks = []
    for f in findings:
        st = Status(f["status"])
        label = _STATUS_LABEL[st]
        detail = f"<p class='detail'>{html.escape(f['detail'])}</p>" if f["detail"] else ""
        metrics = _metrics_table(f["metrics"])
        blocks.append(f"""
<div class="finding finding-{st.value}">
  <div class="finding-head">
    <span class="status status-{st.value}">{label}</span>
    <h3>{html.escape(f['title'])}</h3>
  </div>
  <p class="summary">{html.escape(f['summary'])}</p>
  {detail}{metrics}
</div>""")
    return "<div class='wrap'><h2>检验项明细</h2>" + "".join(blocks) + "</div>"


def _metrics_table(metrics: dict) -> str:
    if not metrics:
        return ""
    rows = []
    for k, val in metrics.items():
        if isinstance(val, (dict, list)):
            continue  # 复杂结构不塞进小表
        if isinstance(val, float):
            val = f"{val:.4g}"
        rows.append(f"<tr><td>{html.escape(k)}</td><td>{html.escape(str(val))}</td></tr>")
    if not rows:
        return ""
    return f"<table class='metrics'>{''.join(rows)}</table>"


def _guesswork_section(g: dict) -> str:
    reasons = "".join(f"<li>{html.escape(r)}</li>" for r in g.get("reduction_reasons", []))
    return f"""
<div class="wrap">
  <h2>有效熵与猜测空间估算</h2>
  <div class="guessbox">
    <div class="guess-bits">{g['effective_bits']:.1f}<span>bit 有效熵</span></div>
    <div class="guess-detail">
      <p>逐位置香农熵合计 {g['shannon_bits']:.1f} bit；
         最小熵合计 {g['min_entropy_bits']:.1f} bit；
         可变位置 {g['variable_positions']} 个。</p>
      <p>{html.escape(g['attack_times'])}</p>
      <ul>{reasons}</ul>
      <p class="detail">估算方法：对每个位置取最小熵 −log₂(p_max) 后求和，
      这是比香农熵更保守的猜测阻力下界；若已恢复出预测器/种子，则有效熵直接折减至 0。</p>
    </div>
  </div>
</div>"""


def _charts_section(findings: list[dict]) -> str:
    charts = [f["chart"] for f in findings if f.get("chart")]
    if not charts:
        return ""
    blocks = []
    for spec in charts:
        blocks.append(f"<div class='chart-card'><h3>{html.escape(spec['title'])}</h3>"
                      f"{_draw_chart(spec)}</div>")
    return "<div class='wrap'><h2>可视化</h2><div class='charts'>" + "".join(blocks) + "</div></div>"


def _sample_section(sample: dict) -> str:
    examples = "".join(f"<code>{html.escape(e)}</code>" for e in sample["examples"])
    return f"""
<div class="wrap">
  <h2>样本信息</h2>
  <table class="metrics">
    <tr><td>来源</td><td>{html.escape(sample['source'])}</td></tr>
    <tr><td>采集时间戳</td><td>{'有' if sample['has_timestamps'] else '无（时间类检验跳过）'}</td></tr>
    <tr><td>字母表</td><td><code>{html.escape(sample['alphabet'])}</code></td></tr>
  </table>
  <p class="sub">样本示例：{examples}</p>
</div>"""


def _methodology_footer() -> str:
    return """
<div class="wrap">
  <h2>检验方法与局限</h2>
  <ul class="method">
    <li><b>字符/字节均匀性</b>：卡方拟合优度检验（α=1%），配合归一化香农熵交叉验证。</li>
    <li><b>位置熵</b>：逐位置香农熵与最小熵，定位熵偏低的固定字符段。</li>
    <li><b>位置相关性</b>：列联表 Cramér's V 扫描相邻与抽样非相邻位置对。</li>
    <li><b>序号关联</b>：首比特游程检验 + 相邻整数值 Spearman 秩相关。</li>
    <li><b>时间关联</b>：采集时间与令牌整数（含低 32 位）的 Spearman 相关。</li>
    <li><b>预测性检验</b>：一阶马尔可夫留出测试、LCG 差分 gcd 参数恢复、
        MT19937 时间/弱种子恢复、哈希计数器假设、明文计数器与内嵌时间戳识别。</li>
    <li><b>局限</b>：统计检验只能证伪；样本量不足会漏报；本工具不替代代码审计
        （仍需确认生成端使用 secrets/os.urandom/CSPRNG，且令牌具备有效期、单次使用与绑定属性）。</li>
  </ul>
  <p class="sub">报告由 token_rng_audit 生成，全部计算在本地完成，样本数据不离开本机。</p>
</div>"""


# ---------------------------------------------------------------------------
# 内联 SVG 图表
# ---------------------------------------------------------------------------

_PALETTE = ["#4f8ff7", "#e07a5f", "#43aa8b", "#b56576", "#f2cc8f", "#8e7dbe"]


def _draw_chart(spec: dict) -> str:
    kind = spec["kind"]
    if kind == "bar":
        return _svg_bar(spec)
    if kind == "histogram":
        return _svg_histogram(spec)
    if kind == "line":
        return _svg_line(spec)
    if kind == "scatter":
        return _svg_scatter(spec)
    return ""


def _svg_bar(spec: dict) -> str:
    x, y = spec["x"], spec["y"]
    w, h = 720, 260
    pad_l, pad_b, pad_t = 40, 34, 14
    ymax = max(y) * 1.15 or 1
    bw = (w - pad_l - 10) / max(1, len(x))
    bars = []
    for i, (label, val) in enumerate(zip(x, y)):
        bh = (h - pad_b - pad_t) * val / ymax
        bx = pad_l + i * bw
        by = h - pad_b - bh
        bars.append(
            f"<rect x='{bx:.1f}' y='{by:.1f}' width='{max(1, bw - 1):.1f}' "
            f"height='{bh:.1f}' fill='{_PALETTE[0]}'><title>{html.escape(str(label))}: "
            f"{val}</title></rect>")
        if len(x) <= 32:
            bars.append(
                f"<text x='{bx + bw / 2:.1f}' y='{h - pad_b + 14}' font-size='9' "
                f"text-anchor='middle' class='ax'>{html.escape(str(label))}</text>")
    exp = spec.get("expected")
    line = ""
    if exp:
        ey = h - pad_b - (h - pad_b - pad_t) * exp / ymax
        line = (f"<line x1='{pad_l}' x2='{w - 8}' y1='{ey:.1f}' y2='{ey:.1f}' "
                f"stroke='{_PALETTE[1]}' stroke-dasharray='5,4'/>"
                f"<text x='{w - 10}' y='{ey - 4:.1f}' text-anchor='end' font-size='10' "
                f"fill='{_PALETTE[1]}'>均匀期望</text>")
    return f"<svg viewBox='0 0 {w} {h}' class='svg'>{''.join(bars)}{line}{_axes(w, h, pad_l, pad_b)}</svg>"


def _svg_histogram(spec: dict) -> str:
    y = spec["y"]
    w, h = 720, 240
    pad_l, pad_b, pad_t = 40, 24, 12
    ymax = max(y) * 1.15 or 1
    bw = (w - pad_l - 8) / len(y)
    bars = []
    for i, val in enumerate(y):
        bh = (h - pad_b - pad_t) * val / ymax
        bars.append(
            f"<rect x='{pad_l + i * bw:.1f}' y='{h - pad_b - bh:.1f}' "
            f"width='{max(0.5, bw):.1f}' height='{bh:.1f}' fill='{_PALETTE[2]}'>"
            f"<title>{i}: {val}</title></rect>")
    avg = sum(y) / len(y)
    ey = h - pad_b - (h - pad_b - pad_t) * avg / ymax
    line = (f"<line x1='{pad_l}' x2='{w - 8}' y1='{ey:.1f}' y2='{ey:.1f}' "
            f"stroke='{_PALETTE[1]}' stroke-dasharray='5,4'/>")
    return f"<svg viewBox='0 0 {w} {h}' class='svg'>{''.join(bars)}{line}{_axes(w, h, pad_l, pad_b)}</svg>"


def _svg_line(spec: dict) -> str:
    w, h = 720, 260
    pad_l, pad_b, pad_t = 44, 30, 14
    series = spec["series"]
    all_y = [v for s in series for v in s["y"]]
    ymax = max(all_y + [spec.get("hmax", 0) or 0]) * 1.1 or 1
    x = spec["x"]
    xmax = max(x) if x else 1
    polylines, legend = [], []
    for si, s in enumerate(series):
        pts = []
        for xv, yv in zip(x, s["y"]):
            px = pad_l + (w - pad_l - 10) * (xv / xmax if xmax else 0)
            py = h - pad_b - (h - pad_b - pad_t) * yv / ymax
            pts.append(f"{px:.1f},{py:.1f}")
        color = _PALETTE[si % len(_PALETTE)]
        polylines.append(
            f"<polyline fill='none' stroke='{color}' stroke-width='1.8' "
            f"points='{' '.join(pts)}'/>")
        legend.append(
            f"<span class='lg'><i style='background:{color}'></i>{html.escape(s['name'])}</span>")
    hmax_line = ""
    if spec.get("hmax"):
        hy = h - pad_b - (h - pad_b - pad_t) * spec["hmax"] / ymax
        hmax_line = (f"<line x1='{pad_l}' x2='{w - 10}' y1='{hy:.1f}' y2='{hy:.1f}' "
                     f"stroke='var(--muted)' stroke-dasharray='3,3'/>")
    return (f"<svg viewBox='0 0 {w} {h}' class='svg'>{''.join(polylines)}{hmax_line}"
            f"{_axes(w, h, pad_l, pad_b)}</svg><div class='legend'>{''.join(legend)}</div>")


def _svg_scatter(spec: dict) -> str:
    x, y = spec["x"], spec["y"]
    w, h = 720, 280
    pad_l, pad_b, pad_t = 48, 30, 14
    xmax = max(x) or 1
    # 大整数取对数显示，避免量级压扁
    y_abs = [abs(v) for v in y] or [1]
    import math
    ymax = max(y_abs) * 1.05 or 1
    pts = []
    for xv, yv in zip(x, y):
        px = pad_l + (w - pad_l - 10) * xv / xmax
        py = h - pad_b - (h - pad_b - pad_t) * (abs(yv) / ymax)
        pts.append(f"<circle cx='{px:.1f}' cy='{py:.1f}' r='2.6' fill='{_PALETTE[0]}'>"
                   f"<title>t+{xv:.2f}s: {yv}</title></circle>")
    return (f"<svg viewBox='0 0 {w} {h}' class='svg'>{''.join(pts)}"
            f"{_axes(w, h, pad_l, pad_b)}</svg>"
            f"<p class='sub'>{html.escape(spec.get('x_label', ''))}；纵轴为令牌整数绝对值</p>")


def _axes(w: int, h: int, pad_l: int, pad_b: int) -> str:
    return (f"<line x1='{pad_l}' y1='{h - pad_b}' x2='{w - 8}' y2='{h - pad_b}' "
            f"stroke='var(--border)'/>"
            f"<line x1='{pad_l}' y1='10' x2='{pad_l}' y2='{h - pad_b}' "
            f"stroke='var(--border)'/>")


# ---------------------------------------------------------------------------
# 样式
# ---------------------------------------------------------------------------

_HTML_HEAD = """<!doctype html><html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>令牌随机性评估报告</title>
<style>
:root{
  --bg:#f6f7fb; --card:#ffffff; --fg:#1c2333; --muted:#6b7280; --border:#e3e6ee;
  --pass:#1a9e6e; --warn:#c77800; --fail:#d64545; --info:#5b6b8c;
  --accent:#2f6fed;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    color-scheme: dark;
    --bg:#11141b; --card:#1a1f2b; --fg:#e6e9f0; --muted:#98a1b3; --border:#2a3142;
    --pass:#35d399; --warn:#f0a83b; --fail:#ff6b6b; --info:#8fa3c8; --accent:#7aa7ff;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:14px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;}
.wrap{max-width:980px;margin:0 auto;padding:0 20px}
h1{font-size:24px;margin:.2em 0} h2{font-size:19px;margin:1.6em 0 .7em} h3{font-size:15px;margin:0 0 .5em}
.sub{color:var(--muted);font-size:13px}
.hero{padding:34px 0 28px;color:#fff}
.hero strong{color:#fff}
.hero-strong{background:linear-gradient(135deg,#0f7a55,#159a6e)}
.hero-moderate{background:linear-gradient(135deg,#9a6200,#c77800)}
.hero-weak{background:linear-gradient(135deg,#a52d2d,#d64545)}
.hero-predictable{background:linear-gradient(135deg,#7a1630,#c0274b)}
.hero .explain{opacity:.92;max-width:820px}
.headline{font-size:16px;font-weight:600}
.grade{display:inline-block;background:rgba(255,255,255,.18);border:1px solid rgba(255,255,255,.35);
  padding:3px 14px;border-radius:999px;font-weight:700;letter-spacing:2px;margin-bottom:10px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:22px 0}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px}
.card-k{color:var(--muted);font-size:12px} .card-v{font-size:17px;font-weight:650;margin-top:3px}
.finding{background:var(--card);border:1px solid var(--border);border-left-width:4px;
  border-radius:10px;padding:14px 16px;margin:12px 0}
.finding-pass{border-left-color:var(--pass)} .finding-warn{border-left-color:var(--warn)}
.finding-fail{border-left-color:var(--fail)} .finding-info{border-left-color:var(--info)}
.finding-head{display:flex;align-items:center;gap:10px}
.status{font-size:12px;font-weight:700;padding:2px 9px;border-radius:999px;color:#fff;white-space:nowrap}
.status-pass{background:var(--pass)} .status-warn{background:var(--warn)}
.status-fail{background:var(--fail)} .status-info{background:var(--info)}
.summary{margin:.5em 0 .2em} .detail{color:var(--muted);font-size:13px;margin:.3em 0}
table{border-collapse:collapse;width:100%;margin:8px 0}
.metrics td{border:1px solid var(--border);padding:5px 10px;font-size:13px}
.metrics td:first-child{color:var(--muted);width:220px}
.compare th,.compare td{border:1px solid var(--border);padding:8px 10px;text-align:left}
.compare th{background:var(--card);font-size:13px}
.num{text-align:right;font-variant-numeric:tabular-nums}
.warn-txt{color:var(--warn)} .fail-txt{color:var(--fail)}
.pill{padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700;color:#fff}
.pill-strong{background:var(--pass)} .pill-moderate{background:var(--warn)}
.pill-weak,.pill-predictable{background:var(--fail)}
.warnbox{background:var(--card);border:1px solid var(--warn);border-radius:10px;
  padding:12px 16px;margin:16px 0}
.guessbox{display:flex;gap:22px;background:var(--card);border:1px solid var(--border);
  border-radius:12px;padding:20px;flex-wrap:wrap}
.guess-bits{font-size:44px;font-weight:750;color:var(--accent);min-width:180px;text-align:center}
.guess-bits span{display:block;font-size:13px;color:var(--muted);font-weight:400}
.guess-detail{flex:1;min-width:280px}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:14px}
.chart-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px;
  min-width:0}
.svg{width:100%;height:auto;display:block}
.ax{fill:var(--muted)} .legend{display:flex;gap:14px;margin-top:6px;flex-wrap:wrap}
.lg{font-size:12px;color:var(--muted);display:inline-flex;align-items:center;gap:5px}
.lg i{width:12px;height:3px;display:inline-block;border-radius:2px}
code{background:var(--bg);border:1px solid var(--border);border-radius:5px;padding:1px 6px;
  font-size:12px;word-break:break-all}
.method li{margin:.35em 0}
.verdict-list li{margin:.4em 0}
@media (max-width:560px){.charts{grid-template-columns:1fr}.guess-bits{font-size:34px}}
</style></head>"""


def render_json(result: dict) -> str:
    return json.dumps(result, ensure_ascii=False, indent=2)
