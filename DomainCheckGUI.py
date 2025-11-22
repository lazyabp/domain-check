import sys
import json
import socket
import ssl
import aiohttp
import asyncio
import subprocess
from PyQt5 import QtWidgets, QtCore, QtGui


TEST_DNS = {
    "Google(8.8.8.8)": "8.8.8.8",
    "Cloudflare(1.1.1.1)": "1.1.1.1",
    "AliDNS(223.5.5.5)": "223.5.5.5",
    "114DNS(114.114.114.114)": "114.114.114.114"
}

TEST_PORTS = [80, 443]
TIMEOUT = 4

OVERSEAS_APIS = [
    "http://localhost:8000/check?domain=",
]


def dig_query(domain, dns):
    try:
        result = subprocess.check_output(
            ["dig", "+short", domain, "@%s" % dns],
            stderr=subprocess.STDOUT,
            timeout=TIMEOUT
        ).decode().strip().split("\n")
        return [r for r in result if r]
    except:
        return []


def tcp_connect(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT):
            return True
    except:
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
    except:
        return False


class Worker(QtCore.QThread):
    finished = QtCore.pyqtSignal(dict, dict, dict)

    def __init__(self, domain):
        super().__init__()
        self.domain = domain

    async def async_overseas_test(self):
        async def fetch(api):
            url = api + self.domain
            async with aiohttp.ClientSession() as s:
                try:
                    async with s.get(url, timeout=TIMEOUT+2) as r:
                        return await r.json()
                except:
                    return {"error": f"海外 API 不可达: {api}"}

        tasks = [fetch(api) for api in OVERSEAS_APIS]
        results = await asyncio.gather(*tasks)
        return dict(zip(OVERSEAS_APIS, results))

    def local_test(self):
        result = {"dns": {}, "connectivity": {}}

        for name, dns in TEST_DNS.items():
            ips = dig_query(self.domain, dns)
            result["dns"][name] = ips

        all_ips = set(ip for ips in result["dns"].values() for ip in ips)
        result["all_ips"] = list(all_ips)

        for ip in all_ips:
            result["connectivity"][ip] = {}
            for p in TEST_PORTS:
                result["connectivity"][ip][f"tcp_{p}"] = tcp_connect(ip, p)

            if tcp_connect(ip, 443):
                result["connectivity"][ip]["tls"] = tls_handshake(self.domain)

        return result

    def compare(self, local, overseas):
        report = {}

        local_ips = set(local["all_ips"])
        overseas_ips = set()

        for api, r in overseas.items():
            if "dns" in r:
                for k, v in r["dns"].items():
                    for ip in v:
                        overseas_ips.add(ip)

        report["local_ips"] = list(local_ips)
        report["overseas_ips"] = list(overseas_ips)

        if local_ips != overseas_ips:
            report["conclusion"] = "域名疑似被墙"
        else:
            report["conclusion"] = "未发现明显封锁"

        return report

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        local = self.local_test()
        overseas = loop.run_until_complete(self.async_overseas_test())
        summary = self.compare(local, overseas)

        self.finished.emit(local, overseas, summary)


class App(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("域名被墙检测器（GUI版）")
        self.setGeometry(200, 200, 650, 550)

        self.layout = QtWidgets.QVBoxLayout(self)

        self.input = QtWidgets.QLineEdit()
        self.input.setPlaceholderText("请输入要检测的域名（例如：google.com）")
        self.layout.addWidget(self.input)

        self.button = QtWidgets.QPushButton("开始检测")
        self.button.clicked.connect(self.start_test)
        self.layout.addWidget(self.button)

        self.output = QtWidgets.QTextEdit()
        self.output.setReadOnly(True)
        self.layout.addWidget(self.output)

    def log(self, msg):
        self.output.append(msg)
        self.output.ensureCursorVisible()

    def start_test(self):
        domain = self.input.text().strip()
        if not domain:
            self.log("❌ 请输入域名")
            return

        self.output.clear()
        self.log(f"开始检测：{domain}\n")

        self.worker = Worker(domain)
        self.worker.finished.connect(self.show_result)
        self.worker.start()

    def show_result(self, local, overseas, summary):
        self.log("=== 国内检测结果 ===")
        self.log(json.dumps(local, indent=2, ensure_ascii=False))

        self.log("\n=== 海外检测结果 ===")
        self.log(json.dumps(overseas, indent=2, ensure_ascii=False))

        self.log("\n=== 综合判断 ===")
        self.log(json.dumps(summary, indent=2, ensure_ascii=False))

        with open("report.json", "w", encoding="utf-8") as f:
            json.dump(
                {"local": local, "overseas": overseas, "summary": summary},
                f,
                ensure_ascii=False,
                indent=2
            )
        self.log("\n📄 已生成报告 report.json")


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    gui = App()
    gui.show()
    sys.exit(app.exec_())
