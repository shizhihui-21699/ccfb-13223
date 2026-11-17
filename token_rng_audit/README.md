# token_rng_audit — 令牌随机性评估工具

面向**授权渗透测试**的重置链接 / 会话令牌随机性评估工具。纯 Python 标准库实现，
无第三方依赖，结果输出为**单文件离线 HTML 报告**（内联 SVG 图表）+ 机器可读 JSON。

> 仅限在获得书面授权的系统与本地靶场上使用。本工具只做被动统计分析与
> 受控的本地算法验证，不会对目标发起爆破或未授权请求。

## 它能回答什么问题

一批“看着随机”的令牌，到底能不能被猜出来？工具从两个层面回答：

1. **统计层面**——字符/字节分布是否均匀、各位置熵是否充足、位置之间是否相关、
   与采集序号或时间是否相关；
2. **可预测性层面**——不只是“熵低”，而是实际尝试**恢复生成算法**：
   线性同余参数、MT19937 弱种子、哈希计数器、明文计数器等，并给出留出集预测准确率。

## 检验项（16 项）

| 类别 | 检验 | 方法 |
|------|------|------|
| 基础 | 长度一致性、重复令牌、结构指纹（UUID/JWT/固定前后缀） | 规则匹配 |
| 分布 | 字符分布均匀性、字节级频率 | 卡方拟合优度（α=0.001）+ 归一化熵 |
| 熵 | 逐位置香农熵 / 最小熵 | 定位熵偏低的固定字符段 |
| 相关性 | 位置间相关性 | Bergsma 修正的 Cramér's V（稀疏计数） |
| 序列 | 序号关联 | 游程检验 + 滞后 1 阶 Spearman |
| 时间 | 时间关联、内嵌时间戳识别 | Spearman + 多单位时间戳匹配 |
| 预测 | 一阶马尔可夫留出预测 | 仅在可变位置评估，对比众数基线 |
| 预测 | LCG 参数恢复 | 差分 gcd + 模线性方程（支持 2 的幂/素模数） |
| 预测 | MT19937 种子恢复 | 固定弱种子 + 时间戳 + 时间戳×1000+计数器 |
| 预测 | 哈希计数器假设 | 不依赖起始值的连续计数器验证（md5/sha1/sha256） |
| 预测 | 明文计数器识别 | 恒定步长 + 留出预测 |
| 总评 | 有效熵与猜测空间 | 逐位置最小熵求和，已恢复预测器时折减至 0 |

**有效熵**采用逐位置最小熵 `−log₂(p_max)` 之和（比香农熵更保守的猜测阻力下界），
并按在线/离线攻击速率换算成可读的破解耗时。

## 快速开始

需要 Python 3.10+，无第三方依赖。

```bash
# 1. 一键演示：内置靶场，对 1 个安全 + 6 个缺陷生成器批量评估
python3 -m token_rng_audit demo --count 300 --out-dir reports
#    产出 reports/<generator>.html、reports/comparison.html

# 2. 单独启动本地靶场（仅绑定 127.0.0.1）
python3 -m token_rng_audit lab --port 8765

# 3. 从接口批量采集（留档为 jsonl，支持 {n} 分页、正则/JSON 路径提取）
python3 -m token_rng_audit collect \
    --url 'http://127.0.0.1:8765/token/lcg' \
    --regex '"token": "([0-9a-f]+)"' --count 200 --out evidence/lcg.jsonl

# 4. 评估：接口 / 留档文件 / 本地文件 三选一
python3 -m token_rng_audit analyze --samples evidence/lcg.jsonl --out reports/lcg.html
python3 -m token_rng_audit analyze --url 'http://127.0.0.1:8765/batch/secure?n=250' \
    --json-path tokens --count 250 --out reports/secure.html
python3 -m token_rng_audit import --file tokens.txt --out reports/from-file.html
```

支持的导入格式：`.txt`（每行一个令牌，或 `token,timestamp`）、`.json` / `.jsonl`、
`.csv`（自动识别 token 列与时间列）。

## 内置靶场生成器

| 生成器 | 缺陷 | 预期判定 |
|--------|------|----------|
| `secure` | `secrets.token_urlsafe`（CSPRNG） | 强 |
| `counter` | 明文递增计数器，可枚举 | 可预测 |
| `hash_counter` | `sha256(计数器)`，哈希不增加不可预测性 | 可预测 |
| `timestamp` | 秒级时间戳 + 16bit 随机后缀 | 可预测 |
| `lcg` | 线性同余，参数可从输出恢复 | 可预测 |
| `mt_time_seed` | MT19937 + 时间戳/计数器弱种子 | 可预测 |
| `uuid_v1` | 暴露 MAC 与时间戳，随机位仅 14bit | 可预测 |

## 分级含义

- **强（STRONG）**：各检验未发现弱点，有效熵 ≥128bit，表现与 CSPRNG 一致；
- **中等（MODERATE）**：通过但有可疑信号或安全裕量不足；
- **弱（WEAK）**：存在明确统计弱点或有效熵 <64bit；
- **可预测（PREDICTABLE）**：恢复出了具体预测器/种子，或有效熵 <32bit，
  攻击者可直接计算其他用户令牌。

## 重要局限

统计检验**只能证伪、不能证明安全**——通过全部检验不等于令牌一定安全。
本工具不替代代码审计，仍需在生成端确认：

- 使用 `secrets` / `os.urandom` / 认证过的 CSPRNG，而非 `random` 模块；
- 令牌至少 128bit 熵，具备有效期、单次使用、与会话/用户绑定属性；
- 样本量建议 ≥200，低于 30 时报告会明确提示统计功效不足。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 目录结构

```
token_rng_audit/
├── token_rng_audit/
│   ├── stats.py       # 熵、卡方、Cramér's V、Spearman、游程
│   ├── tokens.py      # 样本归一化、编码识别/解码、批次编码裁决
│   ├── structure.py   # UUID/JWT/固定前后缀指纹
│   ├── predict.py     # 马尔可夫、LCG、MT 种子、哈希计数器、猜测空间
│   ├── checks.py      # 16 项单项检验
│   ├── analyzer.py    # 检验编排与总评
│   ├── collector.py   # HTTP 采集 + 文件导入
│   ├── report.py      # 单文件 HTML/SVG 报告
│   ├── generators.py  # 靶场生成器
│   ├── lab_server.py  # 本地靶场 HTTP 服务
│   └── cli.py         # 命令行入口
└── tests/test_toolkit.py
```
