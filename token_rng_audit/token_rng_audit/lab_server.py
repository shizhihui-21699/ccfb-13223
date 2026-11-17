"""本地靶场：模拟重置链接 / 会话令牌接口，内置 7 种生成方式。

仅绑定 127.0.0.1，供授权测试使用：
  secure          secrets.token_urlsafe（CSPRNG，安全基线）
  counter         明文递增计数器
  timestamp       秒级时间戳 + 短随机后缀
  lcg             可恢复参数的线性同余生成器
  mt_time_seed    random.Random(时间戳) 的 MT19937 输出
  hash_counter    sha256(递增计数器)
  uuid_v1         含 MAC 与时间戳的 UUIDv1

接口：
  GET /token/<generator>                单个令牌
  GET /batch/<generator>?n=200          批量
  GET /generators                       生成器清单与缺陷说明
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import generators

HOST = "127.0.0.1"
PORT_DEFAULT = 8765


class LabHandler(BaseHTTPRequestHandler):
    server_version = "TokenRNGLab/1.0"

    def log_message(self, fmt, *args):  # 静默默认访问日志，CLI 层自行打印
        return

    def _send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        if parts == ["generators"]:
            self._send_json({"generators": generators.CATALOG})
            return
        if len(parts) == 2 and parts[0] in ("token", "batch"):
            name = parts[1]
            gen = generators.get(name)
            if gen is None:
                self._send_json({"error": f"未知生成器 {name}"}, 404)
                return
            qs = parse_qs(parsed.query)
            n = min(int(qs.get("n", ["1"])[0]), 1000)
            if parts[0] == "token":
                self._send_json({"generator": name, "token": gen(),
                                 "timestamp": time.time()})
            else:
                self._send_json({"generator": name, "count": n,
                                 "tokens": [gen() for _ in range(n)],
                                 "timestamp": time.time()})
            return
        self._send_json({
            "service": "token-rng-lab",
            "endpoints": ["/generators", "/token/<name>", "/batch/<name>?n=200"],
        }, 404)


def serve(host: str = HOST, port: int = PORT_DEFAULT) -> None:
    server = ThreadingHTTPServer((host, port), LabHandler)
    print(f"[lab] 靶场已启动：http://{host}:{port}（仅本机访问，Ctrl+C 停止）")
    print("[lab] 生成器：" + "、".join(g["name"] for g in generators.CATALOG))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[lab] 已停止")
    finally:
        server.server_close()


if __name__ == "__main__":
    port = int(os.environ.get("LAB_PORT", PORT_DEFAULT))
    serve(port=port)
