#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Domain Firewall Check API
域名被墙检测 API 接口（支持并发）
"""

import socket
import ssl
import subprocess
import asyncio
import concurrent.futures
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Union
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

# 线程池用于执行阻塞操作
executor = concurrent.futures.ThreadPoolExecutor(max_workers=20)

# -----------------------
# FastAPI 应用
# -----------------------

app = FastAPI(
    title="域名被墙检测 API",
    description="检测域名是否被墙（DNS / TCP / TLS / HTTP 多维度检测）",
    version="1.0.0"
)


# -----------------------
# 请求模型
# -----------------------

class DomainRequest(BaseModel):
    domain: str


# -----------------------
# 工具函数（同步版本，在线程池中执行）
# -----------------------

def dig_query(domain: str, dns: str) -> list:
    """DNS 查询"""
    try:
        result = subprocess.check_output(
            ["dig", "+short", domain, f"@{dns}"],
            stderr=subprocess.STDOUT,
            timeout=TIMEOUT
        ).decode().strip().split("\n")
        return [r for r in result if r and r.strip()]
    except Exception:
        return []


def tcp_connect(ip: str, port: int) -> bool:
    """TCP 连接测试"""
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT):
            return True
    except Exception:
        return False


def tls_handshake(domain: str) -> Union[str, bool]:
    """TLS 握手测试"""
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


def http_head(ip: str, domain: str) -> bool:
    """HTTP HEAD 请求测试"""
    try:
        conn = socket.create_connection((ip, 80), timeout=TIMEOUT)
        request = f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode()
        conn.send(request)
        resp = conn.recv(50)
        return resp.startswith(b"HTTP")
    except Exception:
        return False


# -----------------------
# 异步工具函数
# -----------------------

async def async_dig_query(domain: str, dns: str) -> tuple[str, list]:
    """异步 DNS 查询"""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(executor, dig_query, domain, dns)
    return dns, result


async def async_tcp_connect(ip: str, port: int) -> tuple[str, int, bool]:
    """异步 TCP 连接测试"""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(executor, tcp_connect, ip, port)
    return ip, port, result


async def async_tls_handshake(domain: str) -> Union[str, bool]:
    """异步 TLS 握手测试"""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(executor, tls_handshake, domain)
    return result


async def async_http_head(ip: str, domain: str) -> tuple[str, bool]:
    """异步 HTTP HEAD 请求测试"""
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(executor, http_head, ip, domain)
    return ip, result


# -----------------------
# 主检测函数（并发版本）
# -----------------------

async def check_domain(domain: str) -> dict:
    """检测域名是否被墙（并发执行）"""
    start_time = time.time()
    report = {
        "domain": domain,
        "dns": {},
        "connectivity": {},
        "summary": {},
        "timestamp": time.time()
    }

    # ---- 并发执行 DNS 检测 ----
    dns_tasks = [(name, async_dig_query(domain, dns)) for name, dns in TEST_DNS.items()]
    dns_results = await asyncio.gather(*[task[1] for task in dns_tasks])
    
    dns_dict = {}
    for (name, _), (dns_ip, ips) in zip(dns_tasks, dns_results):
        dns_dict[name] = ips
    
    report["dns"] = dns_dict

    # ---- 分析 DNS 是否污染 ----
    all_ips = set(ip for ips in dns_dict.values() for ip in ips)
    report["summary"]["all_ips"] = list(all_ips)
    report["summary"]["dns_pollution"] = len(all_ips) > 1
    report["summary"]["dns_status"] = "疑似 DNS 污染" if len(all_ips) > 1 else "DNS 解析一致"

    if not all_ips:
        report["summary"]["error"] = "无法获得有效解析结果"
        report["summary"]["elapsed_time"] = time.time() - start_time
        return report

    # ---- 并发执行 TCP 连接测试 ----
    tcp_tasks = []
    for ip in all_ips:
        for port in TEST_PORTS:
            tcp_tasks.append(async_tcp_connect(ip, port))
    
    tcp_results = await asyncio.gather(*tcp_tasks)
    
    # 组织 TCP 结果
    for ip in all_ips:
        report["connectivity"][ip] = {}
    
    for ip, port, result in tcp_results:
        report["connectivity"][ip][f"tcp_{port}"] = result

    # ---- 并发执行 TLS 和 HTTP 测试 ----
    tls_tasks = []
    http_tasks = []
    
    for ip in all_ips:
        # 只有 TCP 443 通的情况下才测试 TLS
        if report["connectivity"][ip].get("tcp_443", False):
            tls_tasks.append((ip, async_tls_handshake(domain)))
        
        # 只有 TCP 80 通的情况下才测试 HTTP
        if report["connectivity"][ip].get("tcp_80", False):
            http_tasks.append((ip, async_http_head(ip, domain)))
    
    # 并发执行 TLS 测试
    if tls_tasks:
        tls_results = await asyncio.gather(*[task[1] for task in tls_tasks])
        for (ip, _), result in zip(tls_tasks, tls_results):
            report["connectivity"][ip]["tls"] = result
    
    # 并发执行 HTTP 测试
    if http_tasks:
        http_results = await asyncio.gather(*[task[1] for task in http_tasks])
        for (ip, _), result in zip(http_tasks, http_results):
            report["connectivity"][ip]["http"] = result

    # ---- 生成综合判断 ----
    blocked_indicators = []
    
    # DNS 污染检测
    if report["summary"]["dns_pollution"]:
        blocked_indicators.append("DNS污染")
    
    # TLS Reset 检测
    for ip, conn in report["connectivity"].items():
        if conn.get("tls") == "TLS-Reset":
            blocked_indicators.append("TLS-Reset(疑似SNI封锁)")
            break
    
    # TCP 连接失败检测
    all_tcp_failed = True
    for ip, conn in report["connectivity"].items():
        if conn.get("tcp_80") or conn.get("tcp_443"):
            all_tcp_failed = False
            break
    
    if all_tcp_failed:
        blocked_indicators.append("TCP连接失败")
    
    report["summary"]["blocked_indicators"] = blocked_indicators
    report["summary"]["is_blocked"] = len(blocked_indicators) > 0
    report["summary"]["conclusion"] = "域名疑似被墙" if report["summary"]["is_blocked"] else "未发现明显封锁"
    report["summary"]["elapsed_time"] = round(time.time() - start_time, 2)

    return report


# -----------------------
# API 路由
# -----------------------

@app.get("/")
async def root():
    """API 根路径"""
    return {
        "message": "域名被墙检测 API",
        "version": "1.0.0",
        "endpoints": {
            "GET /check": "检测域名（查询参数：domain）",
            "POST /check": "检测域名（请求体：{\"domain\": \"example.com\"}）"
        }
    }


@app.get("/check")
async def check_domain_get(domain: str = Query(..., description="要检测的域名", example="google.com")):
    """GET 方式检测域名"""
    if not domain or not domain.strip():
        raise HTTPException(status_code=400, detail="域名参数不能为空")
    
    domain = domain.strip()
    try:
        result = await check_domain(domain)
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"检测过程中发生错误: {str(e)}")


@app.post("/check")
async def check_domain_post(request: DomainRequest):
    """POST 方式检测域名"""
    domain = request.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="域名参数不能为空")
    
    try:
        result = await check_domain(domain)
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"检测过程中发生错误: {str(e)}")


@app.get("/health")
async def health():
    """健康检查"""
    return {"status": "ok"}


# -----------------------
# 启动应用
# -----------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
