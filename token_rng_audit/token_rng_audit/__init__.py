"""token_rng_audit — 令牌随机性评估工具（授权渗透测试用）。

模块划分：
    stats      基础统计（熵、卡方、相关系数、p 值近似）
    tokens     令牌样本的归一化、解码（hex/base64/整数字节）
    checks     单项检验，每个检验返回 Finding
    predict    预测性检验（马尔可夫、LCG 恢复、MT 种子恢复、哈希假设）
    analyzer   检验套件编排与总评
    collector  从 HTTP 接口批量采集 / 从文件导入
    report     单文件 HTML 报告生成（内联 SVG）
    cli        命令行入口
"""

__version__ = "1.0.0"
