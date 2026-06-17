"""Run with:  python -m fortitoolbox   (or the `fortitoolbox` console script)."""
from nicegui import ui

from .app import build


def serve(port: int = 8080, show: bool = True):
    @ui.page("/")
    def index():
        build()

    # Bind to localhost by default: the app holds live SSH creds + raw firewall
    # output and has no auth. Override host explicitly to expose on a LAN.
    ui.run(title="FortiToolbox", dark=True, reload=False, port=port, host="127.0.0.1",
           favicon="\U0001F6E1\uFE0F", show=show)


if __name__ in {"__main__", "__mp_main__"}:
    serve()
