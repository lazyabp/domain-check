#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Domain Firewall Check Script
一键检测域名是否被墙（DNS / TCP / TLS / HTTP 多维度）
"""

import socket
import ssl
import subprocess
import json
import time

# -----------------------
# 配置区域
# -----------------------

TEST_DNS = {
    "Google(8.8.8.8)": "8.8.8.8",
    "Cloudflare(1.1.1.1)": "1.1.1.1",
    "Ali(223.5.5.5)": "223.5.5.5",
    "114DNS(114.114.114.114)": "114.114.114.114"
}

TEST_PORTS = [80, 443]

TIMEOUT = 4


# -----------------------
# 工具函数
# -----------------------

def dig_query(domain, dns):
    try:
        result = subprocess.check_output(
            ["dig", "+short", domain, "@%s" % dns],
            stderr=subprocess.STDOUT,
            timeout=TIMEOUT
        ).decode().strip().split("\n")
        return [r for r in result if r]
    except Exception:
        return []


def tcp_connect(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT):
            return True
    except Exception:
        return False


def tls_handshake(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(TIMEOUT)
            s.connect((domain, 443))
            s.do_handshake()
        return True
    except ssl.SSLError:
        return "TLS-Reset"
    except Exception:
        return False


def http_head(ip):
    try:
        conn = socket.create_connection((ip, 80), timeout=TIMEOUT)
        request = b"HEAD / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
        conn.send(request)
        resp = conn.recv(50)
        return resp.startswith(b"HTTP")
    except Exception:
        return False


# -----------------------
# 主函数
# -----------------------

def run(domain):
    print("\n============================")
    print("  域名检测工具")
    print("============================\n")
    print(f"目标域名：{domain}")
    print("开始检测...\n")
    time.sleep(0.8)

    report = {"domain": domain, "dns": {}, "connectivity": {}}

    # ---- DNS 检测 ----
    print("🔍 DNS 检测中...\n")
    dns_results = {}
    for name, dns in TEST_DNS.items():
        ips = dig_query(domain, dns)
        dns_results[name] = ips
        print(f"  {name:<20} => {ips}")

    report["dns"] = dns_results

    # ---- 分析 DNS 是否污染 ----
    all_ips = set(ip for ips in dns_results.values() for ip in ips)
    if len(all_ips) > 1:
        print("\n⚠️ 检测到不同 DNS 解析结果 → 疑似 DNS 污染")
    else:
        print("\n✔ DNS 解析一致 → 未发现明显污染")

    print("\n----------------------------\n")

    # ---- TCP/TLS/HTTP 测试 ----
    ips = list(all_ips)
    if not ips:
        print("❌ 无法获得有效解析结果，后续无法继续测试。")
        return report

    for ip in ips:
        print(f"🧪 测试 IP: {ip}")
        report["connectivity"][ip] = {}

        # TCP 80/443
        for p in TEST_PORTS:
            ok = tcp_connect(ip, p)
            report["connectivity"][ip][f"tcp_{p}"] = ok
            print(f"  TCP {p:<3}: {'✔ 通' if ok else '❌ 不通'}")

        # TLS
        if tcp_connect(ip, 443):
            tls = tls_handshake(domain)
            report["connectivity"][ip]["tls"] = tls
            if tls is True:
                print("  TLS : ✔ 握手成功")
            elif tls == "TLS-Reset":
                print("  TLS : ❌ RST（疑似 SNI 封锁）")
            else:
                print("  TLS : ❌ 握手失败")

        # HTTP
        if tcp_connect(ip, 80):
            head = http_head(ip)
            report["connectivity"][ip]["http"] = head
            print(f"  HTTP: {'✔ 返回正常' if head else '❌ 无响应'}")

        print()

    print("============================")
    print("检测结束\n")

    print("📄 JSON报告（可保存）：")
    print(json.dumps(report, indent=2, ensure_ascii=False))

    return report


# -----------------------
# 入口
# -----------------------

if __name__ == "__main__":
    domain = input("请输入要检测的域名：").strip()
    run(domain)
