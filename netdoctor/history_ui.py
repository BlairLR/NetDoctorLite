"""Dialogs for saved reports and comparisons between detection times."""

from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QDialog, QHBoxLayout, QHeaderView, QLabel,
    QListWidget, QListWidgetItem, QMessageBox, QPlainTextEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout,
)

from .compare import IncompatibleRuns, compare_runs
from .history import HistoryError
from .report import snapshot_report


def snapshot_caption(snapshot):
    return f"{snapshot.display_time}  ·  {snapshot.mode_label}  ·  {snapshot.vpn}"


def open_comparison(parent, before, after, *, baseline=False):
    title = "与基准对比" if baseline else "两次检测对比"
    before_label, after_label = ("基准", "本次") if baseline else ("较早", "较晚")
    try:
        rows = compare_runs(before, after)
    except IncompatibleRuns as exc:
        QMessageBox.information(parent, title, str(exc))
        return

    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    dialog.resize(950, 620)
    layout = QVBoxLayout(dialog)
    layout.addWidget(QLabel(before_label + "检测  " + snapshot_caption(before)))
    layout.addWidget(QLabel(after_label + "检测  " + snapshot_caption(after)))
    changed = QCheckBox("只看变化")
    changed.setChecked(True)
    layout.addWidget(changed)
    description = QLabel("改善和恶化按连接状态、HTTP 响应及同条件耗时判断。出口变化单独标记。")
    description.setWordWrap(True)
    layout.addWidget(description)
    table = QTableWidget(0, 4)
    table.setHorizontalHeaderLabels(("检测项目", before_label, after_label, "变化"))
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setAlternatingRowColors(True)
    table.verticalHeader().hide()
    header = table.horizontalHeader()
    for column in range(3):
        header.setSectionResizeMode(column, QHeaderView.ResizeMode.Stretch)
    header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
    layout.addWidget(table)
    count = QLabel()
    layout.addWidget(count)
    close = QPushButton("关闭")
    close.clicked.connect(dialog.accept)
    layout.addWidget(close, alignment=Qt.AlignmentFlag.AlignRight)

    def refresh():
        visible = [row for row in rows if not changed.isChecked() or row.verdict != "无变化"]
        table.setRowCount(len(visible))
        colors = {"改善": "#126645", "恶化": "#a02626", "已变化": "#2159a5"}
        for index, row in enumerate(visible):
            for column, value in enumerate((row.metric, row.before, row.after, row.verdict)):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if column == 3 and row.verdict in colors:
                    item.setForeground(QColor(colors[row.verdict]))
                table.setItem(index, column, item)
        count.setText(f"显示 {len(visible)} 项，共 {len(rows)} 项")

    changed.toggled.connect(refresh)
    refresh()
    dialog.exec()


class HistoryDialog(QDialog):
    def __init__(self, store, parent=None):
        super().__init__(parent)
        self.store = store
        self.setWindowTitle("本地检测历史")
        self.resize(870, 650)
        layout = QVBoxLayout(self)
        self.info = QLabel()
        self.info.setWordWrap(True)
        layout.addWidget(self.info)
        self.items = QListWidget()
        self.items.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.items.itemSelectionChanged.connect(self.refresh_selection)
        layout.addWidget(self.items, 1)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("选择一条记录查看报告，选中两条可对比。")
        layout.addWidget(self.detail, 2)
        row = QHBoxLayout()
        self.baseline_button = QPushButton("设为基准")
        self.baseline_button.clicked.connect(self.set_baseline)
        self.clear_button = QPushButton("取消基准")
        self.clear_button.clicked.connect(lambda: self.apply(self.store.set_baseline, None))
        self.compare_button = QPushButton("对比所选两次")
        self.compare_button.clicked.connect(self.compare_selected)
        self.delete_button = QPushButton("删除所选")
        self.delete_button.clicked.connect(self.delete_selected)
        close = QPushButton("关闭")
        close.clicked.connect(self.accept)
        for button in (self.baseline_button, self.clear_button, self.compare_button,
                       self.delete_button, close):
            row.addWidget(button)
        layout.addLayout(row)
        self.reload()

    def reload(self):
        self.items.clear()
        for record in self.store.records:
            prefix = "基准 · " if record.id == self.store.baseline_id else ""
            item = QListWidgetItem(prefix + snapshot_caption(record))
            item.setData(Qt.ItemDataRole.UserRole, record.id)
            self.items.addItem(item)
        self.info.setText(
            "历史文件无法读取，现有文件已保留。" if self.store.read_error else
            f"本机保存 {len(self.store.records)} 条。按住 Ctrl 可选择两条记录。"
        )
        self.refresh_selection()

    def selected(self):
        ids = {item.data(Qt.ItemDataRole.UserRole) for item in self.items.selectedItems()}
        return [record for record in self.store.records if record.id in ids]

    def refresh_selection(self):
        records = self.selected()
        writable = not self.store.read_error
        self.baseline_button.setEnabled(writable and len(records) == 1)
        self.clear_button.setEnabled(writable and self.store.baseline_id is not None)
        self.compare_button.setEnabled(len(records) == 2)
        self.delete_button.setEnabled(writable and bool(records))
        if len(records) != 1:
            self.detail.clear()
            return
        snapshot = records[0]
        direct = snapshot.result.direct_exit
        proxy = snapshot.result.proxy_exit
        preview = ["【本机历史预览】", f"直连公网出口 IP：{direct.ip or '未取得'}"]
        if proxy:
            preview.append(f"代理公网出口 IP：{proxy.ip or '未取得'}")
        self.detail.setPlainText("\n".join(preview) + "\n\n" + snapshot_report(snapshot))

    def apply(self, operation, argument):
        try:
            operation(argument)
        except HistoryError as exc:
            QMessageBox.warning(self, "历史记录", str(exc))
        self.reload()

    def set_baseline(self):
        self.apply(self.store.set_baseline, self.selected()[0].id)

    def compare_selected(self):
        earlier, later = sorted(self.selected(), key=lambda item: datetime.fromisoformat(item.time))
        open_comparison(self, earlier, later)

    def delete_selected(self):
        ids = [record.id for record in self.selected()]
        prompt = f"删除选中的 {len(ids)} 条检测记录？"
        if self.store.baseline_id in ids:
            prompt += " 删除基准记录时会同时取消基准。"
        if QMessageBox.question(self, "删除历史", prompt) == QMessageBox.StandardButton.Yes:
            self.apply(self.store.delete_many, ids)
