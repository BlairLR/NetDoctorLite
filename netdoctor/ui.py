from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QLocale, QObject, Qt, QThread, Signal, Slot
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QFrame,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QProgressBar, QPushButton, QScrollArea, QSpinBox, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget, QAbstractItemView,
)

from .compare import IncompatibleRuns, compare_runs, profile_mismatches
from .history import HistoryError, HistoryStore, Snapshot, VPN_STATES, make_profile
from .history_ui import HistoryDialog, open_comparison, snapshot_caption
from .model import COMMON_PORTS, DiagnosticResult, Proxy, custom_url, hostname
from .network import detect_proxy, diagnose
from .report import comparison, describe, port_rows, snapshot_report, status, summary
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
    failed = Signal(str)

    def __init__(self, url, proxy, mode, vpn, baseline_profile=None):
        super().__init__()
        self.url = url
        self.proxy = proxy
        self.mode = mode
        self.vpn = vpn
        self.baseline_profile = baseline_profile

    @Slot()
    def run(self):
        try:
            started = datetime.now().astimezone().isoformat(timespec="microseconds")
            note = ""
            candidate_ports = set()
            if self.mode == "auto":
                self.progress.emit(2, "正在查找并验证本机代理")
                self.proxy, note = detect_proxy(candidate_ports)
                if self.baseline_profile is not None:
                    profile = make_profile(self.url, self.mode, self.proxy)
                    mismatches = profile_mismatches(self.baseline_profile, profile)
                    if mismatches:
                        self.failed.emit("复测未开始。自动选择的代理与基准不一致。\n" + note)
                        return
            result = diagnose(self.url, self.proxy, self.progress.emit, candidate_ports=candidate_ports)
            snapshot = Snapshot.capture(result, self.url, self.mode, self.proxy, self.vpn, note, started)
            self.done.emit(snapshot)
        except Exception:
            self.failed.emit("检测未能完成，请重新开始。")
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


def country_label(check):
    if check is None:
        return "未检测"
    code = check.country_code
    if not code:
        return "未取得"
    common_names = {
        "CN": "中国", "HK": "中国香港", "MO": "中国澳门", "TW": "中国台湾",
        "US": "美国", "JP": "日本", "SG": "新加坡", "KR": "韩国", "GB": "英国",
        "DE": "德国", "NL": "荷兰", "FR": "法国", "CA": "加拿大", "AU": "澳大利亚",
    }
    if code in common_names:
        return f"{common_names[code]} ({code})"
    territory = QLocale.codeToTerritory(code)
    if territory == QLocale.Territory.AnyTerritory:
        return code
    name = QLocale.territoryToString(territory)
    return f"{name} ({code})"


def route_table_rows(result: DiagnosticResult):
    def exit_value(check):
        if check is None:
            return "未检测"
        if check.ip is None:
            return check.detail
        source = "Cloudflare" if "Cloudflare" in check.detail else "ipify"
        return f"{check.ip} · {source}"

    return (
        ("HTTPS", website_https(result.direct_https), website_https(result.proxy_https)),
        ("公网出口 IP", exit_value(result.direct_exit), exit_value(result.proxy_exit)),
        ("出口国家／地区（估算）", country_label(result.direct_exit), country_label(result.proxy_exit)),
    )


class Window(QMainWindow):
    def __init__(self, history=None):
        super().__init__()
        self.setWindowTitle(f"NetDoctor Lite v{__version__} · 网络诊断")
        self.resize(1000, 860)
        self.setMinimumSize(760, 550)
        self._thread = None
        self._worker = None
        self._report = ""
        self.history = history if history is not None else HistoryStore()
        self.current = None
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
        self.vpn = QComboBox()
        self.vpn.addItems(VPN_STATES)
        form.addRow("VPN 状态（手动标记）", self.vpn)
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
        self.used_proxy = label("本次使用的代理：等待检测", "muted", True)
        result.addWidget(self.used_proxy)
        history = self.card("基准与历史")
        self.baseline_info = label("", "muted", True)
        history.addWidget(self.baseline_info)
        history_actions = QHBoxLayout()
        self.set_baseline_button = QPushButton("本次设为基准")
        self.set_baseline_button.clicked.connect(self.set_current_baseline)
        self.retest_button = QPushButton("按基准复测")
        self.retest_button.clicked.connect(self.retest_baseline)
        self.compare_baseline_button = QPushButton("查看基准对比")
        self.compare_baseline_button.clicked.connect(self.show_baseline_comparison)
        self.clear_baseline_button = QPushButton("取消基准")
        self.clear_baseline_button.clicked.connect(self.clear_baseline)
        self.history_button = QPushButton("历史记录")
        self.history_button.clicked.connect(self.show_history)
        for button in (self.set_baseline_button, self.retest_button, self.compare_baseline_button,
                       self.clear_baseline_button, self.history_button):
            history_actions.addWidget(button)
        history_actions.addStretch()
        history.addLayout(history_actions)
        section = self.card("网站连接 · 直连与代理")
        self.show_dns_tcp = QCheckBox("显示 DNS 和 TCP 443")
        section.addWidget(self.show_dns_tcp, alignment=Qt.AlignmentFlag.AlignLeft)
        self.sites = table(("目标", "直连 DNS", "直连 TCP 443", "直连 HTTPS", "代理 HTTPS"))
        header = self.sites.horizontalHeader()
        for column in (3, 4):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Stretch)
        section.addWidget(self.sites)
        self.show_dns_tcp.toggled.connect(self.toggle_dns_tcp)
        self.toggle_dns_tcp(False)
        section.addWidget(label("HTTP 4xx / 5xx 表示服务器已响应并返回错误。", "muted", True))
        section = self.card("外网通路与公网出口 · Cloudflare")
        self.routes = table(("检测项目", "直连", "代理"))
        for column in (1, 2):
            self.routes.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.Stretch)
        section.addWidget(self.routes)
        section.addWidget(label("出口是测试服务实际看到的公网 IP，国家／地区按该 IP 估算。"
                                "代理分流时，不同网站可能走不同出口。", "muted", True))
        self.compare = label("等待检测", "muted", True)
        section.addWidget(self.compare)
        section = self.card("详细信息")
        self.show_details = QCheckBox("展开代理隧道和本机配置")
        section.addWidget(self.show_details)
        self.details = QWidget()
        details = QVBoxLayout(self.details)
        details.setContentsMargins(0, 0, 0, 0)
        self.tunnel_detail = label("代理隧道：等待检测", "muted", True)
        details.addWidget(self.tunnel_detail)
        self.ports = table(("候选端口", "TCP", "监听地址", "PID", "进程"))
        details.addWidget(self.ports)
        self.config = label("等待检测", "muted", True)
        details.addWidget(self.config)
        section.addWidget(self.details)
        self.show_details.toggled.connect(self.details.setVisible)
        self.details.hide()
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
        self.refresh_baseline()

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

    @Slot(bool)
    def toggle_dns_tcp(self, show):
        self.sites.setColumnHidden(1, not show)
        self.sites.setColumnHidden(2, not show)

    def refresh_baseline(self):
        baseline = self.history.baseline
        available = self._thread is None
        compare_ready = False
        if self.history.read_error:
            message = "历史文件无法读取，检测仍可运行。"
        elif baseline is None:
            message = "尚未设置基准。检测完成后可将本次结果设为基准。"
        else:
            message = "基准  " + snapshot_caption(baseline)
            if self.current and self.current.id != baseline.id:
                try:
                    changes = compare_runs(baseline, self.current)
                except IncompatibleRuns as exc:
                    message += "\n" + str(exc)
                else:
                    compare_ready = True
                    message += (f"\n相对基准改善 {sum(row.verdict == '改善' for row in changes)} 项"
                                f"，恶化 {sum(row.verdict == '恶化' for row in changes)} 项。")
        self.baseline_info.setText(message)
        self.set_baseline_button.setEnabled(available and self.current is not None
                                            and not self.history.read_error)
        self.clear_baseline_button.setEnabled(available and baseline is not None)
        self.retest_button.setEnabled(available and baseline is not None)
        self.compare_baseline_button.setEnabled(available and compare_ready)
        self.history_button.setEnabled(available)

    @Slot()
    def set_current_baseline(self):
        try:
            if not any(record.id == self.current.id for record in self.history.records):
                self.history.save(self.current)
            self.history.set_baseline(self.current.id)
        except HistoryError as exc:
            QMessageBox.warning(self, "设置基准", str(exc))
        self.refresh_baseline()

    @Slot()
    def clear_baseline(self):
        try:
            self.history.set_baseline(None)
        except HistoryError as exc:
            QMessageBox.warning(self, "取消基准", str(exc))
        self.refresh_baseline()

    @Slot()
    def show_baseline_comparison(self):
        baseline = self.history.baseline
        if baseline and self.current:
            open_comparison(self, baseline, self.current, baseline=True)

    @Slot()
    def show_history(self):
        self.history.reload()
        HistoryDialog(self.history, self).exec()
        self.refresh_baseline()

    @Slot()
    def retest_baseline(self):
        if self._thread is not None:
            return
        self.history.reload()
        baseline = self.history.baseline
        self.refresh_baseline()
        if baseline is None:
            return
        mode = baseline.profile.mode
        self.enabled.setChecked(mode != "direct")
        if mode != "direct":
            self.proxy_mode.setCurrentIndex(self.proxy_mode.findData(mode))
        if mode == "manual" and baseline.proxy is not None:
            self.proto.setCurrentText(baseline.proxy.protocol)
            self.port.setValue(baseline.proxy.port)
        self.start_detection(baseline.profile)

    @Slot()
    def begin(self):
        self.start_detection()

    def start_detection(self, baseline_profile=None):
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
        mode = "auto" if automatic else "manual" if proxy else "direct"
        if baseline_profile is not None:
            profile = make_profile(url, mode, proxy)
            mismatches = profile_mismatches(baseline_profile, profile, check_proxy=not automatic)
            if mismatches:
                message = "复测未开始，以下参数与基准不一致：" + "、".join(mismatches) + "。"
                if "检测目标" in mismatches:
                    message += "\n请重新输入与基准相同的自定义网址，或清空多余的网址。"
                if "实际代理端点、协议或认证方式" in mismatches:
                    message += "\n请核对代理主机，并按基准时的方式填写认证信息。"
                QMessageBox.information(self, "按基准复测", message)
                return
        self.username.clear()
        self.password.clear()
        self._report = ""
        self.current = None
        self.enabled.setEnabled(False)
        self.proxy_options.setEnabled(False)
        self.vpn.setEnabled(False)
        for widget in (self.start, self.copy, self.export):
            widget.setEnabled(False)
        for widget in (self.sites, self.ports, self.routes):
            fill(widget, [])
        self.config.setText("正在检测…")
        self.used_proxy.setText("本次使用的代理：正在检测…")
        self.tunnel_detail.setText("代理隧道：正在检测…")
        self.compare.setText("正在检测…")
        self.conclusion.setText("正在检测，请稍候。")
        self.set_progress(0, "正在启动检测")
        self._thread = QThread(self)
        self._worker = Worker(url, proxy, mode, self.vpn.currentText(), baseline_profile)
        self.refresh_baseline()
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
    def show_result(self, snapshot):
        self.current = snapshot
        result, proxy, note = snapshot.result, snapshot.proxy, snapshot.note
        self.conclusion.setText(summary(result, proxy, note))
        self.used_proxy.setText("本次检测  " + snapshot_caption(snapshot))
        fill(self.sites, (
            (s.name, status(s.dns), status(s.tcp) if s.dns.ok else "未检测",
             website_https(s.https), website_https(s.proxy_https))
            for s in result.sites
        ))
        for row, site in enumerate(result.sites):
            for column, check in enumerate((site.dns, site.tcp, site.https, site.proxy_https), 1):
                if check is not None:
                    self.sites.item(row, column).setToolTip(describe(check))
        fill(self.ports, port_rows(result.ports, result.listeners))
        self.config.setText("\n".join(result.settings))
        tunnel = result.proxy_tunnel
        self.tunnel_detail.setText("代理隧道：" + (describe(tunnel) if tunnel else "未检测"))
        fill(self.routes, route_table_rows(result))
        self.compare.setText(note if note and proxy is None else comparison(result))
        self._report = snapshot_report(snapshot)
        try:
            self.history.save(snapshot)
        except HistoryError as exc:
            self.activity.setText(str(exc))
            self.conclusion.setText(self.conclusion.text() + "\n" + str(exc))
        self.copy.setEnabled(True)
        self.export.setEnabled(True)

    @Slot(str)
    def show_failure(self, message):
        self.conclusion.setText(message)
        self.used_proxy.setText("本次使用的代理：未取得")
        self.tunnel_detail.setText("代理隧道：未取得")
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
        self.vpn.setEnabled(True)
        self.refresh_baseline()

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
