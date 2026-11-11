import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from PySide6.QtCore import QTimer

from netdoctor.history import HistoryStore
from netdoctor.ui import Window, make_app


def run(history=None, *, smoke=False):
    app = make_app()
    window = Window(history)
    window.show()
    if smoke:
        # Exercise the packaged Qt platform plugin, worker and report flow.
        def verify():
            if window._thread is None:
                ok = (window.isVisible() and window.progress.value() == 100
                      and window.sites.rowCount() == 4 and window.routes.rowCount() == 3
                      and window.copy.isEnabled() and len(history.records) == 1)
                app.exit(0 if ok else 2)

        poll = QTimer()
        poll.timeout.connect(verify)
        poll.start(100)
        QTimer.singleShot(0, window.start.click)
        QTimer.singleShot(80000, lambda: app.exit(3))
    return app.exec()


if __name__ == "__main__":
    if sys.argv[1:] == ["--smoke-test"]:
        with TemporaryDirectory(prefix="netdoctor-smoke-") as directory:
            raise SystemExit(run(HistoryStore(Path(directory) / "history.json"), smoke=True))
    raise SystemExit(run())
