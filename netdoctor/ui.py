from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, Signal, Slot
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QFrame,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QProgressBar, QPushButton, QScrollArea, QSpinBox, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget, QAbstractItemView,
)

from .model import COMMON_PORTS, Proxy, custom_url, hostname
from .network import detect_proxy, diagnose
from .report import comparison, describe, port_rows, report, route_rows, status, summary
from .version import __version__

STYLE = """
QMainWindow, QScrollArea, QWidget#page {background:#f2f5fa;}
QLabel {color:#172641;}
QLabel#title {font-size:29px;font-weight:700;}
QLabel#muted {color:#475b75;}
QLabel#section {font-size:17px;font-weight:700;color:#132849;}
QLabel#conclusion {background:#e9f2ff;color:#15365f;padding:12px;border-radius:7px;}
QFrame#card {background:white;border:1px solid #dce5f1;border-radius:10px;}
QLineEdit,QComboBox,QSpinBox {background:white;color:#172641;border:1px solid #aebdd1;
 border-radius:5px;padding:6px;selection-background-color:#1263c7;}
QPushButton {background:white;color:#173458;border:1px solid #aebdd1;border-radius:6px;padding:8px 14px;}
QPushButton:hover {background:#eaf3ff;}
QPushButton#start {background:#155cc4;color:white;border:none;font-weight:700;padding:11px 26px;}
QPushButton#start:hover {background:#114b9f;}
QPushButton:disabled,QPushButton#start:disabled {background:#e4eaf2;color:#536680;}
QProgressBar {background:#dfe8f4;border:none;border-radius:4px;color:#172641;text-align:center;}
QProgressBar::chunk {background:#74aeff;border-radius:4px;}
QTableWidget {background:white;alternate-background-color:#f3f7fd;color:#172641;border:0;}
QHeaderView::section {background:#eaf0f8;color:#20395b;border:0;padding:6px;}
"""


class Worker(QObject):
    progress = Signal(int, str)
    done = Signal(object)
    failed = Signal()

    def __init__(self, url, proxy, automatic):
        super().__init__()
        self.url = url
        self.proxy = proxy
        self.automatic = automatic

    @Slot()
    def run(self):
        try:
            note = ""
            if self.automatic:
                self.progress.emit(2, "正在查找并验证本机代理")
                self.proxy, note = detect_proxy()
            result = diagnose(self.url, self.proxy, self.progress.emit)
            self.done.emit((result, self.proxy, note))
        except Exception:
            self.failed.emit()
        finally:
            self.url = self.proxy = None


def label(text, name="", wrap=False):
    item = QLabel(text)
    item.setObjectName(name)
    item.setWordWrap(wrap)
    return item


def table(headers):
    item = QTableWidget(0, len(headers))
    item.setHorizontalHeaderLabels(headers)
    item.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    item.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
    item.setAlternatingRowColors(True)
    item.setShowGrid(False)
    item.verticalHeader().hide()
    item.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    item.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    item.horizontalHeader().setStretchLastSection(True)
    item.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    item.setFixedHeight(34)
    return item


def fill(widget, rows):
    rows = list(rows)
    widget.setRowCount(len(rows))
    for i, row in enumerate(rows):
        for j, value in enumerate(row):
            item = QTableWidgetItem(value)
            item.setToolTip(value)
            widget.setItem(i, j, item)
    widget.resizeRowsToContents()
    widget.setFixedHeight(widget.horizontalHeader().sizeHint().height() +
                          sum(widget.rowHeight(i) for i in range(len(rows))))


def website_https(check):
    if check is None:
        return "未检测"
    result = f"HTTP {check.code}" if check.code is not None else check.detail
    return f"{result} · {check.ms} 毫秒" if check.ms is not None else result


class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"NetDoctor Lite v{__version__} · 网络诊断")
        self.resize(1000, 860)
        self.setMinimumSize(760, 550)
        self._thread = None
        self._worker = None
        self._report = ""
        shell = QWidget()
        shell.setObjectName("page")
        outer = QVBoxLayout(shell)
        outer.setContentsMargins(20, 14, 20, 12)
        outer.setSpacing(10)
        outer.addWidget(label("NetDoctor Lite", "title"))
        outer.addWidget(label("网络诊断  /  网站直连、代理监听与外网通路", "muted"))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        page = QWidget()
        page.setObjectName("page")
        self.body = QVBoxLayout(page)
        self.body.setContentsMargins(0, 0, 8, 0)
        self.body.setSpacing(10)
        scroll.setWidget(page)
        outer.addWidget(scroll, 1)

        settings = self.card("检测设置")
        form = QFormLayout()
        self.url = QLineEdit()
        self.url.setPlaceholderText("可选，例如 https://example.com")
        self.url.setMaxLength(2048)
        self.url.setEchoMode(QLineEdit.EchoMode.PasswordEchoOnEdit)
        form.addRow("自定义网站", self.url)
        self.enabled = QCheckBox("对比直连与代理")
        form.addRow("", self.enabled)
        self.proxy_options = QWidget()
        options = QVBoxLayout(self.proxy_options)
        options.setContentsMargins(0, 0, 0, 0)
        self.proxy_mode = QComboBox()
        self.proxy_mode.addItem("自动检测本机代理（推荐）", "auto")
        for port in COMMON_PORTS:
            self.proxy_mode.addItem(f"常用本机端口 · {port}", port)
        self.proxy_mode.addItem("手动填写代理", "manual")
        options.addWidget(self.proxy_mode)
        self.proxy_fields = QWidget()
        row = QHBoxLayout(self.proxy_fields)
        row.setContentsMargins(0, 0, 0, 0)
        self.proto = QComboBox()
        self.proto.addItems(["HTTP", "SOCKS5"])
        self.host = QLineEdit("127.0.0.1")
        self.host.setPlaceholderText("主机或 IP")
        self.host.setEchoMode(QLineEdit.EchoMode.PasswordEchoOnEdit)
        self.host.setMaxLength(255)
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(7890)
        self.username = QLineEdit()
        self.username.setPlaceholderText("用户名（选填）")
        self.password = QLineEdit()
        self.password.setPlaceholderText("密码（选填）")
        for field in (self.username, self.password):
            field.setEchoMode(QLineEdit.EchoMode.Password)
            field.setMaxLength(255)
        for widget in (self.proto, self.host, self.port, self.username, self.password):
            row.addWidget(widget)
        options.addWidget(self.proxy_fields)
        self.proxy_options.hide()
        self.enabled.toggled.connect(self.proxy_options.setVisible)
        self.proxy_mode.currentIndexChanged.connect(self.change_proxy_mode)
        self.change_proxy_mode()
        form.addRow("代理设置", self.proxy_options)
        settings.addLayout(form)
        settings.addWidget(label("自动模式每次重新查找本机代理。需要认证或自定义地址时，可手动填写。", "muted", True))
        settings.addWidget(label("直连忽略系统与环境代理；出口通过 Cloudflare 查询，必要时改用 api.ipify.org。"
                                 "代理凭据仅在本次测试中使用。", "muted", True))
        result = self.card("诊断结论")
        self.conclusion = label("点击「开始检测」查看诊断结果。", "conclusion", True)
        result.addWidget(self.conclusion)
        section = self.card("网站连接 · 直连与代理")
        self.sites = table(("目标", "直连 DNS", "直连 TCP 443", "直连 HTTPS", "代理 HTTPS"))
        header = self.sites.horizontalHeader()
        for column in (3, 4):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Stretch)
        section.addWidget(self.sites)
        section.addWidget(label("两条通路分别测试 HTTPS。DNS 和 TCP 443 仅指直连。"
                                 "HTTP 4xx / 5xx 表示网站有响应，但访问可能受限。", "muted", True))
        section = self.card("本机代理端口及设置")
        self.ports = table(("端口", "TCP", "监听地址", "PID", "进程"))
        section.addWidget(self.ports)
        self.config = label("等待检测", "muted", True)
        section.addWidget(self.config)
        section = self.card("外网通路 · Cloudflare")
        self.routes = table(("检测项", "结果"))
        section.addWidget(self.routes)
        self.compare = label("等待检测", "muted", True)
        section.addWidget(self.compare)
        self.body.addStretch()

        actions = QHBoxLayout()
        self.start = QPushButton("开始检测")
        self.start.setObjectName("start")
        self.start.clicked.connect(self.begin)
        self.copy = QPushButton("复制诊断结果")
        self.copy.clicked.connect(self.copy_result)
        self.export = QPushButton("导出 TXT")
        self.export.clicked.connect(self.save_result)
        self.copy.setEnabled(False)
        self.export.setEnabled(False)
        self.activity = label("就绪", "muted")
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setFixedWidth(112)
        for widget in (self.start, self.progress, self.activity):
            actions.addWidget(widget)
        actions.addStretch()
        actions.addWidget(self.copy)
        actions.addWidget(self.export)
        outer.addLayout(actions)
        self.setCentralWidget(shell)

    def card(self, title):
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 10, 14, 12)
        layout.addWidget(label(title, "section"))
        self.body.addWidget(frame)
        return layout

    def change_proxy_mode(self):
        mode = self.proxy_mode.currentData()
        self.proxy_fields.setVisible(mode != "auto")
        if isinstance(mode, int):
            self.host.setText("127.0.0.1")
            self.port.setValue(mode)

    @Slot()
    def begin(self):
        if self._thread is not None:
            return
        try:
            raw = self.url.text().strip()
            url = custom_url(raw) if raw else None
        except ValueError:
            QMessageBox.warning(self, "网址无效", "请输入有效的 HTTPS 网址，不要在网址中填写用户名或密码。")
            return
        proxy = None
        automatic = self.enabled.isChecked() and self.proxy_mode.currentData() == "auto"
        if self.enabled.isChecked() and not automatic:
            try:
                host = hostname(self.host.text().strip().removeprefix("[").removesuffix("]"))
                user, password = self.username.text(), self.password.text()
                proto = self.proto.currentText()
                if (password and not user) or any(ord(c) < 32 or ord(c) == 127 for c in user + password):
                    raise ValueError
                if proto == "HTTP":
                    if ":" in user:
                        raise ValueError
                    (user + password).encode("latin-1")
                elif user and (not password or any(len(v.encode("utf-8")) > 255 for v in (user, password))):
                    raise ValueError
                proxy = Proxy(proto, host, self.port.value(), user, password)
            except ValueError:
                QMessageBox.warning(self, "代理设置无效", "请检查主机、端口和认证信息。SOCKS5 认证须填写用户名和密码。")
                return
        self.username.clear()
        self.password.clear()
        self._report = ""
        self.enabled.setEnabled(False)
        self.proxy_options.setEnabled(False)
        for widget in (self.start, self.copy, self.export):
            widget.setEnabled(False)
        for widget in (self.sites, self.ports, self.routes):
            fill(widget, [])
        self.config.setText("正在检测…")
        self.compare.setText("正在检测…")
        self.conclusion.setText("正在检测，请稍候。")
        self.set_progress(0, "正在启动检测")
        self._thread = QThread(self)
        self._worker = Worker(url, proxy, automatic)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self.set_progress)
        self._worker.done.connect(self.show_result)
        self._worker.failed.connect(self.show_failure)
        self._worker.done.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self.worker_finished)
        self._thread.start()

    @Slot(int, str)
    def set_progress(self, value, text):
        self.progress.setValue(value)
        self.activity.setText(text)

    @Slot(object)
    def show_result(self, payload):
        result, proxy, note = payload
        ports, local, config, sites, *_ = result
        self.conclusion.setText(summary(result, proxy, note))
        if note and proxy:
            self.proto.setCurrentText(proxy.protocol)
            self.host.setText(proxy.host)
            self.port.setValue(proxy.port)
        fill(self.sites, (
            (s.name, status(s.dns), status(s.tcp) if s.dns.ok else "未检测",
             website_https(s.https), website_https(s.proxy_https))
            for s in sites
        ))
        for row, site in enumerate(sites):
            for column, check in enumerate((site.dns, site.tcp, site.https, site.proxy_https), 1):
                if check is not None:
                    self.sites.item(row, column).setToolTip(describe(check))
        fill(self.ports, port_rows(ports, local))
        self.config.setText("\n".join(config))
        fill(self.routes, ((name, describe(check, show_ip=True)) for name, check in route_rows(result)))
        self.compare.setText(note if note and proxy is None else comparison(result))
        self._report = report(result, proxy, note)
        self.copy.setEnabled(True)
        self.export.setEnabled(True)

    @Slot()
    def show_failure(self):
        self.conclusion.setText("检测未能完成，请重新开始。")
        self.config.setText("未取得结果")
        self.compare.setText("未取得结果")
        self.set_progress(0, "检测失败")

    @Slot()
    def worker_finished(self):
        self._thread.deleteLater()
        self._thread = self._worker = None
        self.start.setEnabled(True)
        self.enabled.setEnabled(True)
        self.proxy_options.setEnabled(True)

    @Slot()
    def copy_result(self):
        QApplication.clipboard().setText(self._report)
        self.activity.setText("已复制脱敏报告")

    @Slot()
    def save_result(self):
        path, _ = QFileDialog.getSaveFileName(self, "导出诊断报告", "NetDoctorLite-报告.txt", "文本文件 (*.txt)")
        if path:
            try:
                Path(path).write_text(self._report, encoding="utf-8-sig")
                self.activity.setText("已导出脱敏报告")
            except OSError:
                QMessageBox.warning(self, "导出失败", "无法写入所选位置，请检查权限或选择其他位置。")

    def closeEvent(self, event):
        if self._thread is not None:
            event.ignore()
            self.activity.setText("请等待本轮检测结束")
        else:
            super().closeEvent(event)


def make_app():
    app = QApplication([])
    app.setApplicationName("NetDoctor Lite")
    app.setFont(QFont("Microsoft YaHei UI", 10))
    app.setStyleSheet(STYLE)
    return app
