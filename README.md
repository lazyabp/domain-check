# 域名被墙检测 API

一个基于 FastAPI 的域名被墙检测服务，支持多维度检测（DNS / TCP / TLS / HTTP）和并发处理。

## 功能特性

- ✅ **多维度检测**：DNS 解析、TCP 连接、TLS 握手、HTTP 响应
- ✅ **并发支持**：所有检测任务并发执行，大幅提升检测速度
- ✅ **DNS 污染检测**：对比多个 DNS 服务器的解析结果，识别 DNS 污染
- ✅ **SNI 封锁检测**：通过 TLS 握手检测 SNI 封锁（TLS-Reset）
- ✅ **RESTful API**：标准的 REST API 接口，支持 GET 和 POST 请求
- ✅ **自动文档**：FastAPI 自动生成交互式 API 文档
- ✅ **JSON 响应**：结构化的 JSON 响应格式，便于集成

## 安装说明

### 1. 环境要求

- Python 3.7+
- 系统需要安装 `dig` 命令（用于 DNS 查询）
  - Linux/macOS: 通常已预装
  - Windows: 需要安装 [BIND](https://downloads.isc.org/isc/bind9/9.17.12/) 或使用 WSL

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

或者手动安装：

```bash
pip install fastapi uvicorn[standard] pydantic
```

## 快速开始

### 启动服务

```bash
python DomainCheckApi.py
```

服务将在 `http://0.0.0.0:8000` 启动。

或者使用 uvicorn 命令：

```bash
uvicorn DomainCheckApi:app --host 0.0.0.0 --port 8000
```

### 访问 API 文档

启动服务后，访问以下地址查看交互式 API 文档：

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## API 接口文档

### 1. 根路径

**GET** `/`

获取 API 基本信息和可用端点。

**响应示例：**

```json
{
  "message": "域名被墙检测 API",
  "version": "1.0.0",
  "endpoints": {
    "GET /check": "检测域名（查询参数：domain）",
    "POST /check": "检测域名（请求体：{\"domain\": \"example.com\"}）"
  }
}
```

### 2. 检测域名（GET）

**GET** `/check?domain={domain}`

通过查询参数传递域名进行检测。

**参数：**

- `domain` (必需): 要检测的域名，例如 `google.com`

**请求示例：**

```bash
curl "http://localhost:8000/check?domain=google.com"
```

**响应示例：**

```json
{
  "domain": "google.com",
  "dns": {
    "Google(8.8.8.8)": ["142.250.191.14"],
    "Cloudflare(1.1.1.1)": ["142.250.191.14"],
    "Ali(223.5.5.5)": ["142.250.191.14"],
    "114DNS(114.114.114.114)": ["142.250.191.14"]
  },
  "connectivity": {
    "142.250.191.14": {
      "tcp_80": true,
      "tcp_443": true,
      "tls": true,
      "http": true
    }
  },
  "summary": {
    "all_ips": ["142.250.191.14"],
    "dns_pollution": false,
    "dns_status": "DNS 解析一致",
    "blocked_indicators": [],
    "is_blocked": false,
    "conclusion": "未发现明显封锁",
    "elapsed_time": 2.35
  },
  "timestamp": 1703123456.789
}
```

### 3. 检测域名（POST）

**POST** `/check`

通过请求体传递域名进行检测。

**请求体：**

```json
{
  "domain": "google.com"
}
```

**请求示例：**

```bash
curl -X POST "http://localhost:8000/check" \
  -H "Content-Type: application/json" \
  -d '{"domain": "google.com"}'
```

**响应格式：** 与 GET 请求相同

### 4. 健康检查

**GET** `/health`

检查服务运行状态。

**响应示例：**

```json
{
  "status": "ok"
}
```

## 响应字段说明

### DNS 检测结果

- `dns`: 各 DNS 服务器的解析结果
  - 键：DNS 服务器名称
  - 值：解析到的 IP 地址列表

### 连通性检测结果

- `connectivity`: 每个 IP 的连通性测试结果
  - `tcp_80`: TCP 80 端口连接是否成功
  - `tcp_443`: TCP 443 端口连接是否成功
  - `tls`: TLS 握手结果
    - `true`: 握手成功
    - `false`: 握手失败
    - `"TLS-Reset"`: TLS 重置（疑似 SNI 封锁）
  - `http`: HTTP 响应是否正常

### 综合判断

- `summary.all_ips`: 所有解析到的 IP 地址列表
- `summary.dns_pollution`: 是否存在 DNS 污染（布尔值）
- `summary.dns_status`: DNS 状态描述
- `summary.blocked_indicators`: 被墙指标列表
  - `"DNS污染"`: 检测到 DNS 污染
  - `"TLS-Reset(疑似SNI封锁)"`: 检测到 TLS 重置
  - `"TCP连接失败"`: 所有 TCP 连接都失败
- `summary.is_blocked`: 是否被墙（布尔值）
- `summary.conclusion`: 最终结论
- `summary.elapsed_time`: 检测耗时（秒）
- `timestamp`: 检测时间戳

## 使用示例

### Python 示例

```python
import requests

# GET 请求
response = requests.get("http://localhost:8000/check", params={"domain": "google.com"})
result = response.json()
print(result["summary"]["conclusion"])

# POST 请求
response = requests.post(
    "http://localhost:8000/check",
    json={"domain": "google.com"}
)
result = response.json()
print(result)
```

### JavaScript/Node.js 示例

```javascript
// GET 请求
fetch('http://localhost:8000/check?domain=google.com')
  .then(response => response.json())
  .then(data => console.log(data));

// POST 请求
fetch('http://localhost:8000/check', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ domain: 'google.com' })
})
  .then(response => response.json())
  .then(data => console.log(data));
```

### cURL 示例

```bash
# GET 请求
curl "http://localhost:8000/check?domain=google.com"

# POST 请求
curl -X POST "http://localhost:8000/check" \
  -H "Content-Type: application/json" \
  -d '{"domain": "google.com"}'
```

## 检测原理

### DNS 检测

通过对比多个 DNS 服务器（Google、Cloudflare、阿里、114DNS）的解析结果，如果结果不一致，则可能存在 DNS 污染。

### TCP 连接检测

测试域名解析到的 IP 地址的 80 和 443 端口是否可连接。如果所有端口都无法连接，可能被墙。

### TLS 握手检测

尝试与服务器建立 TLS 连接。如果收到 TLS-Reset，可能是 SNI 封锁。

### HTTP 检测

发送 HTTP HEAD 请求，检测服务器是否正常响应。

## 配置说明

可以在 `DomainCheckApi.py` 中修改以下配置：

```python
# DNS 服务器配置
TEST_DNS = {
    "Google(8.8.8.8)": "8.8.8.8",
    "Cloudflare(1.1.1.1)": "1.1.1.1",
    "Ali(223.5.5.5)": "223.5.5.5",
    "114DNS(114.114.114.114)": "114.114.114.114"
}

# 测试端口
TEST_PORTS = [80, 443]

# 超时时间（秒）
TIMEOUT = 4

# 线程池大小
executor = concurrent.futures.ThreadPoolExecutor(max_workers=20)
```

## 注意事项

1. **dig 命令依赖**：本工具依赖系统的 `dig` 命令进行 DNS 查询。Windows 系统需要安装 BIND 或使用 WSL。

2. **网络环境**：检测结果受当前网络环境影响。建议在需要检测的网络环境中运行服务。

3. **并发限制**：虽然支持并发，但过多的并发请求可能会影响系统性能。建议根据实际情况调整线程池大小。

4. **超时设置**：默认超时时间为 4 秒。如果网络较慢，可以适当增加超时时间。

5. **安全性**：生产环境使用时，建议：
   - 添加认证机制
   - 限制访问 IP
   - 使用 HTTPS
   - 添加速率限制

## 性能优化

- 所有检测任务并发执行，大幅提升检测速度
- 使用线程池处理阻塞操作，避免阻塞事件循环
- 合理的超时设置，避免长时间等待

## 故障排查

### 问题：dig 命令未找到

**解决方案：**
- Linux/macOS: 安装 dnsutils 或 bind-utils
- Windows: 安装 BIND 或使用 WSL

### 问题：检测结果不准确

**可能原因：**
- 网络环境变化
- DNS 缓存影响
- 防火墙规则

**解决方案：**
- 清除 DNS 缓存
- 在不同网络环境测试
- 检查防火墙设置

## 许可证

本项目采用 MIT 许可证。

## 贡献

欢迎提交 Issue 和 Pull Request！

## 更新日志

### v1.0.0
- 初始版本
- 支持 DNS、TCP、TLS、HTTP 多维度检测
- 支持并发检测
- RESTful API 接口

