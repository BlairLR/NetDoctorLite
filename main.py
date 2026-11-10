import sys

from PySide6.QtCore import QTimer

from netdoctor.ui import Window, make_app


def run():
    app = make_app()
    window = Window()
    window.show()
    if sys.argv[1:] == ["--smoke-test"]:
        # Exercise the packaged Qt platform plugin, worker and report flow.
        def verify():
            if window._thread is None:
                ok = (window.isVisible() and window.progress.value() == 100
                      and window.sites.rowCount() == 4 and window.copy.isEnabled())
                app.exit(0 if ok else 2)

        poll = QTimer()
        poll.timeout.connect(verify)
        poll.start(100)
        QTimer.singleShot(0, window.start.click)
        QTimer.singleShot(80000, lambda: app.exit(3))
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(run())
