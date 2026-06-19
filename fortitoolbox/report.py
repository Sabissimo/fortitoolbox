"""Device report -> PDF, dependency-free (hand-written PDF, standard Helvetica).
Branded header, verdict bar with status pills, per-module sections, footer.
Summary-grade: conclusions + the number that matters, no raw dumps.
"""
from __future__ import annotations

import datetime as _dt
from typing import List, Tuple

PAGE_W, PAGE_H = 595, 842
LEFT = 48
HEADER_H = 56
TOP = PAGE_H - HEADER_H - 24          # content top, below header band
BOTTOM = 48
LINE = 14

C = {
    "pass": (0.247, 0.725, 0.314), "warn": (0.824, 0.600, 0.133),
    "fail": (0.973, 0.318, 0.286), "info": (0.345, 0.651, 1.0),
    "skipped": (0.43, 0.46, 0.50), "error": (0.86, 0.43, 0.16),
}
INK = (0.055, 0.067, 0.086)
ACCENT = (0.93, 0.19, 0.14)
TXT = (0.12, 0.14, 0.17)
MUTED = (0.50, 0.53, 0.58)
PANEL = (0.957, 0.965, 0.973)
LINECOL = (0.85, 0.87, 0.90)


def _esc(s: str) -> str:
    s = (str(s).replace("—", "-").replace("–", "-")
         .replace("→", "->").replace("•", "*"))
    s = s.encode("latin-1", "replace").decode("latin-1")
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


class _Pdf:
    def __init__(self, title="Diagnostic report", subtitle=""):
        self._title, self._subtitle = title, subtitle
        self.pages: List[List[str]] = []
        self._start_page()

    def _ops(self):
        return self.pages[-1]

    # --- primitives -------------------------------------------------------
    def _rect(self, x, y, w, h, color):
        r, g, b = color
        self._ops().append("%.3f %.3f %.3f rg %.1f %.1f %.1f %.1f re f" % (r, g, b, x, y, w, h))

    def _line(self, x1, y1, x2, y2, color, width=1.0):
        r, g, b = color
        self._ops().append("%.3f %.3f %.3f RG %.2f w %.1f %.1f m %.1f %.1f l S"
                           % (r, g, b, width, x1, y1, x2, y2))

    def _txt(self, x, y, s, size=10, bold=False, color=TXT):
        r, g, b = color
        self._ops().append("BT /%s %d Tf %.3f %.3f %.3f rg %.1f %.1f Td (%s) Tj ET"
                           % ("F2" if bold else "F1", size, r, g, b, x, y, _esc(s)))

    def _shield(self, cx, cy, w, color=ACCENT, check=(1, 1, 1)):
        half = w / 2.0
        h = w * 1.25
        pts = [(cx - half, cy + h * 0.40), (cx + half, cy + h * 0.40),
               (cx + half, cy - h * 0.08), (cx, cy - h * 0.55), (cx - half, cy - h * 0.08)]
        r, g, b = color
        path = "%.2f %.2f m " % pts[0] + " ".join("%.2f %.2f l" % p for p in pts[1:]) + " h"
        self._ops().append("%.3f %.3f %.3f rg %s f" % (r, g, b, path))
        cr, cg, cb = check
        self._ops().append(
            "%.3f %.3f %.3f RG %.2f w 1 J 1 j %.2f %.2f m %.2f %.2f l %.2f %.2f l S"
            % (cr, cg, cb, max(1.5, w * 0.10),
               cx - w * 0.24, cy + h * 0.02, cx - w * 0.04, cy - h * 0.16, cx + w * 0.28, cy + h * 0.20))

    def _pill(self, x, y, label, status):
        w = 4 + len(label) * 5.6 + 4
        self._rect(x, y - 2, w, 12, C.get(status, MUTED))
        self._txt(x + 4, y, label, size=7.5, bold=True, color=(1, 1, 1))
        return x + w + 5

    # --- page chrome ------------------------------------------------------
    def _start_page(self):
        self.pages.append([])
        # header band
        self._rect(0, PAGE_H - HEADER_H, PAGE_W, HEADER_H, INK)
        self._rect(0, PAGE_H - HEADER_H - 3, PAGE_W, 3, ACCENT)
        self._shield(LEFT + 8, PAGE_H - HEADER_H / 2.0, 22)
        self._txt(LEFT + 28, PAGE_H - 26, "FortiToolbox", size=17, bold=True, color=(1, 1, 1))
        self._txt(LEFT + 28, PAGE_H - 42, self._title, size=9, color=(0.74, 0.78, 0.82))
        if self._subtitle:
            self._txt(PAGE_W - LEFT - 220, PAGE_H - 42, self._subtitle, size=9, color=(0.74, 0.78, 0.82))
        # footer
        self._rect(0, 36, PAGE_W, 0.6, LINECOL)
        self._txt(LEFT, 24, "github.com/Sabissimo/fortitoolbox", size=8, color=MUTED)
        self._txt(PAGE_W - LEFT - 170, 24,
                  "MIT  -  generated " + _dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
                  size=8, color=MUTED)
        self.y = TOP

    def _space(self, need=LINE):
        if self.y - need < BOTTOM:
            self._start_page()

    # --- content helpers --------------------------------------------------
    def text(self, s, size=10, bold=False, color=TXT, indent=0):
        self._space(size + 4)
        self._txt(LEFT + indent, self.y, s, size, bold, color)
        self.y -= size + 4

    def gap(self, n=6):
        self.y -= n

    def panel_box(self, height):
        self._space(height + 4)
        self._rect(LEFT, self.y - height + 10, PAGE_W - 2 * LEFT, height, PANEL)

    def verdict_bar(self, segs, width=None):
        width = width or (PAGE_W - 2 * LEFT)
        total = sum(c for c, _, _ in segs) or 1
        self._space(18)
        x = LEFT
        y = self.y - 12
        for count, color, _ in segs:
            w = width * count / total if count else 0
            if w >= 1:
                self._rect(x, y, w, 14, color)
                x += w
        self.y -= 20

    def check_row(self, status, title, headline, metrics):
        self._space(LINE * 2)
        x = self._pill(LEFT, self.y, status.upper()[:5], status)
        self._txt(x, self.y, title, size=10, bold=True, color=TXT)
        self.y -= LINE
        if headline:
            self.text(headline, size=8.5, color=MUTED, indent=4)
        if metrics:
            mt = "   ".join("%s: %s" % (k, v) for k, v in metrics)
            self.text(mt, size=8, color=(0.62, 0.65, 0.70), indent=4)

    # --- render -----------------------------------------------------------
    def render(self) -> bytes:
        n = len(self.pages)
        body = {}
        body[1] = "<</Type/Catalog/Pages 2 0 R>>"
        kids, oid = [], 5
        page_ids = []
        for i in range(n):
            content_id, page_id = oid, oid + 1
            stream = "\n".join(self.pages[i])
            body[content_id] = "<</Length %d>>\nstream\n%s\nendstream" % (len(stream), stream)
            body[page_id] = ("<</Type/Page/Parent 2 0 R/MediaBox[0 0 %d %d]"
                             "/Resources<</Font<</F1 3 0 R/F2 4 0 R>>>>/Contents %d 0 R>>"
                             % (PAGE_W, PAGE_H, content_id))
            kids.append("%d 0 R" % page_id)
            oid += 2
        body[2] = "<</Type/Pages/Kids[%s]/Count %d>>" % (" ".join(kids), n)
        body[3] = "<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>"
        body[4] = "<</Type/Font/Subtype/Type1/BaseFont/Helvetica-Bold>>"
        total = max(body)
        out = bytearray(b"%PDF-1.4\n")
        off = {}
        for num in range(1, total + 1):
            off[num] = len(out)
            out += ("%d 0 obj\n%s\nendobj\n" % (num, body[num])).encode("latin-1", "replace")
        xref = len(out)
        out += ("xref\n0 %d\n0000000000 65535 f \n" % (total + 1)).encode()
        for num in range(1, total + 1):
            out += ("%010d 00000 n \n" % off[num]).encode()
        out += ("trailer\n<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n"
                % (total + 1, xref)).encode()
        return bytes(out)


def _mask_serial(s):
    if not s or s == "unknown":
        return s or "-"
    return s[:4] + "*" * max(0, len(s) - 6) + s[-2:]


def build_report_pdf(device, results, active_vdom=None) -> bytes:
    tally = {}
    for r in results:
        tally[r.status.value] = tally.get(r.status.value, 0) + 1
    sub = "%s  %s" % (getattr(device, "model", ""), getattr(device, "version", ""))
    p = _Pdf(title="Diagnostic report", subtitle=sub.strip())

    # device signature
    sig = [("Model", getattr(device, "model", "-")),
           ("Version", getattr(device, "full_version", "") or getattr(device, "version", "-")),
           ("Serial", _mask_serial(getattr(device, "serial", "-"))),
           ("Hostname", getattr(device, "hostname", "-") or "-")]
    if getattr(device, "vdom_mode", False):
        sig.append(("VDOM", active_vdom or getattr(device, "mgmt_vdom", "root")))
    p.panel_box(len(sig) * 13 + 16)
    p.gap(2)
    p.text("DEVICE", size=8, bold=True, color=MUTED, indent=8)
    for k, v in sig:
        p.text("%-9s %s" % (k + ":", v), size=10, indent=8, color=TXT)
    p.gap(8)

    # overall verdict headline
    worst = ("fail" if tally.get("fail") else "warn" if tally.get("warn")
             else "pass" if tally.get("pass") else "info")
    head = {"fail": "NEEDS ATTENTION", "warn": "REVIEW WARNINGS",
            "pass": "HEALTHY", "info": "REVIEWED"}[worst]
    p.text(head, size=16, bold=True, color=C[worst])
    order = ["fail", "warn", "pass", "info", "skipped", "error"]
    segs = [(tally.get(s, 0), C[s], s) for s in order if tally.get(s)]
    if segs:
        p.verdict_bar(segs)
        x = LEFT
        for s in order:
            if tally.get(s):
                x = p._pill(x, p.y, "%s %d" % (s.upper(), tally[s]), s)
        p.y -= LINE
    p.gap(6)

    # checks by module
    modules = []
    for r in results:
        if r.module not in modules:
            modules.append(r.module)
    for mod in modules:
        p.gap(4)
        p._space(20)
        p._line(LEFT, p.y + 11, LEFT, p.y - 2, ACCENT, 2.5)
        p.text(mod, size=12, bold=True, color=INK, indent=8)
        for r in results:
            if r.module == mod:
                p.check_row(r.status.value, r.title, r.headline, r.metrics)
    return p.render()
