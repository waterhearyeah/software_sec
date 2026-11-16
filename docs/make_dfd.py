"""Generates docs/dfd-level0.svg and docs/dfd-level1.svg (no dependencies).

Notation (Yourdon/DeMarco):  rectangle = external entity, circle = process,
open-ended box = data store, arrow = data flow, red dashed box = trust boundary.
    python docs/make_dfd.py
"""
import math
import os

OUT = os.path.dirname(os.path.abspath(__file__))
INK, RED, BLUE, GREY = "#152238", "#b3261e", "#12355b", "#5b6577"

HEAD = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}"
 font-family="Segoe UI, Helvetica, Arial, sans-serif" font-size="14" fill="{ink}">
<defs>
 <marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
  <path d="M0,0 L10,5 L0,10 z" fill="{ink}"/></marker>
</defs>
<rect width="{w}" height="{h}" fill="#ffffff"/>
"""


def text(x, y, lines, size=14, weight="normal", fill=INK, anchor="middle"):
    lines = lines.split("\n")
    y0 = y - (len(lines) - 1) * size * 0.6
    return "".join(
        f'<text x="{x}" y="{y0 + i * size * 1.2:.0f}" text-anchor="{anchor}" dominant-baseline="middle" '
        f'font-size="{size}" font-weight="{weight}" fill="{fill}">{line}</text>\n'
        for i, line in enumerate(lines))


def entity(x, y, label, w=190, h=70):
    return (f'<rect x="{x - w / 2}" y="{y - h / 2}" width="{w}" height="{h}" fill="#eef1f5" '
            f'stroke="{INK}" stroke-width="2"/>\n' + text(x, y, label, 15, "bold"))


def process(x, y, num, label, r=62):
    return (f'<circle cx="{x}" cy="{y}" r="{r}" fill="#e6eef8" stroke="{BLUE}" stroke-width="2"/>\n'
            + text(x, y - 30, num, 12, "bold", BLUE) + text(x, y + 4, label, 13, "bold"))


def store(x, y, num, label, w=180, h=56):
    l, t = x - w / 2, y - h / 2
    return (f'<path d="M{l + w},{t} L{l},{t} L{l},{t + h} L{l + w},{t + h}" fill="#fff8e1" stroke="{INK}" stroke-width="2"/>\n'
            f'<line x1="{l + 34}" y1="{t}" x2="{l + 34}" y2="{t + h}" stroke="{INK}" stroke-width="2"/>\n'
            + text(l + 17, y, num, 12, "bold") + text(l + 34 + (w - 34) / 2, y, label, 13))


def boundary(x, y, w, h, label, lx=None, ly=None):
    lx, ly = (x + 12 if lx is None else lx), (y + 16 if ly is None else ly)
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" fill="none" stroke="{RED}" '
            f'stroke-width="2" stroke-dasharray="9 6"/>\n' + text(lx, ly, label, 13, "bold", RED, "start"))


def flow(p1, p2, tag, r1=0, r2=0, both=True, at=0.5, curve=0):
    """Arrow from p1 to p2, trimmed by r1/r2 at the ends, with a numbered tag."""
    (x1, y1), (x2, y2) = p1, p2
    d = math.hypot(x2 - x1, y2 - y1)
    ux, uy = (x2 - x1) / d, (y2 - y1) / d
    sx, sy, ex, ey = x1 + ux * r1, y1 + uy * r1, x2 - ux * r2, y2 - uy * r2
    start = ' marker-start="url(#a)"' if both else ""
    mx, my = sx + (ex - sx) * at, sy + (ey - sy) * at
    out = (f'<line x1="{sx:.0f}" y1="{sy:.0f}" x2="{ex:.0f}" y2="{ey:.0f}" stroke="{INK}" '
           f'stroke-width="1.6" marker-end="url(#a)"{start}/>\n')
    if tag:
        out += (f'<rect x="{mx - 17:.0f}" y="{my - 11:.0f}" width="34" height="22" rx="11" fill="#fff" '
                f'stroke="{INK}"/>\n' + text(mx, my + 1, tag, 12, "bold"))
    return out


def edge_y(y, h, down):
    return y + (h / 2 if down else -h / 2)


def level0():
    w, h = 1240, 520
    s = HEAD.format(w=w, h=h, ink=INK)
    s += text(w / 2, 30, "Student Portal — Context Diagram (DFD Level 0)", 19, "bold")
    s += boundary(560, 70, 400, 420, "TRUST BOUNDARY — portal (university-hosted)")
    s += entity(140, 190, "Student") + entity(140, 370, "Lecturer")
    s += process(760, 280, "0", "Student\nPortal", r=90)
    s += entity(1110, 280, "Registry\n(accounts &amp; records,\nout of scope)", h=90)
    s += flow((235, 190), (760, 280), "", 0, 92) + flow((235, 370), (760, 280), "", 0, 92)
    s += flow((1015, 280), (760, 280), "", 0, 92, both=False)
    s += text(410, 150, "IN: credentials + OTP, assignment files,\nmessages, contact details\n"
              "OUT: grades, attendance, messages, receipts", 12, fill=GREY)
    s += text(410, 425, "IN: credentials + OTP, messages\n"
              "OUT: submitted files, messages,\ncontact details of own students", 12, fill=GREY)
    s += text(1080, 205, "accounts, enrolments,\ngrades, attendance", 12, fill=GREY)
    s += text(170, 480, "Untrusted zone: user devices + Internet", 13, "bold", RED)
    return s + "</svg>\n"


def level1():
    w, h = 1640, 1010
    s = HEAD.format(w=w, h=h, ink=INK)
    s += text(w / 2, 30, "Student Portal — Data Flow Diagram (Level 1) with Trust Boundaries", 20, "bold")

    ent_y, proc_y, store_y = 130, 480, 830
    P = {"P1": 250, "P5": 590, "P2": 880, "P3": 1170, "P4": 1470}
    D = {"D7": 110, "D2": 310, "D1": 520, "D3": 880, "D4": 1090, "D5": 1300, "D6": 1510}
    student, lecturer = (520, ent_y), (1170, ent_y)

    # zones / trust boundaries
    s += text(40, 70, "UNTRUSTED ZONE — user devices and the Internet", 13, "bold", GREY, "start")
    s += boundary(30, 300, 1580, 300, "TB1  Internet → Web app (HTTPS)")
    s += boundary(450, 345, 1140, 235, "TB2  Authenticated session", 1195, 362)
    s += boundary(30, 720, 1580, 230, "TB3  Application → Data tier (parameterised SQL only, least-privilege service account)", 42, 936)
    s += boundary(1200, 760, 200, 135, "TB4  Upload quarantine", 1212, 777)
    s += f'<line x1="845" y1="60" x2="845" y2="180" stroke="{RED}" stroke-width="2" stroke-dasharray="9 6"/>\n'
    s += text(857, 72, "TB5  Role boundary", 13, "bold", RED, "start")

    s += entity(*student, "Student\n(browser)") + entity(*lecturer, "Lecturer\n(browser)")
    names = {"P1": "Authenticate\n(password + MFA)", "P5": "Manage\nprofile", "P2": "View grades &amp;\nattendance",
             "P3": "Submit / review\nassignments", "P4": "Messaging"}
    nums = {"P1": "1.0", "P5": "5.0", "P2": "2.0", "P3": "3.0", "P4": "4.0"}
    for k, x in P.items():
        s += process(x, proc_y, nums[k], names[k])
    labels = {"D7": "Audit log", "D2": "Sessions", "D1": "Users &amp;\ncredentials", "D3": "Grades &amp;\nattendance",
              "D4": "Submission\nmetadata", "D5": "Uploaded\nfiles", "D6": "Messages"}
    for k, x in D.items():
        s += store(x, store_y + (20 if k == "D5" else 0), k, labels[k], w=170)

    sb, lb = (student[0], ent_y + 35), (lecturer[0], ent_y + 35)
    R = 64
    for tag, src, dst, at in [("F1", sb, "P1", .45), ("F5", sb, "P5", .5), ("F2", sb, "P2", .45),
                              ("F3", sb, "P3", .3), ("F4", sb, "P4", .22)]:
        s += flow((src[0] + {"F1": -60, "F5": -10, "F2": 30, "F3": 60, "F4": 85}[tag], src[1]),
                  (P[dst], proc_y), tag, 0, R, at=at)
    for tag, dst, dx, at in [("F6", "P1", -85, .85), ("F9", "P5", -55, .55), ("F7", "P3", 0, .5), ("F8", "P4", 60, .5)]:
        s += flow((lb[0] + dx, lb[1]), (P[dst], proc_y), tag, 0, R, at=at, both=tag != "F9")

    top = store_y - 28
    for tag, p, d, at in [("F10", "P1", "D7", .55), ("F11", "P1", "D2", .55), ("F12", "P1", "D1", .55),
                          ("F13", "P5", "D1", .55), ("F14", "P2", "D3", .5), ("F15", "P3", "D4", .55),
                          ("F16", "P3", "D5", .55), ("F17", "P4", "D6", .5)]:
        ty = top + (20 if d == "D5" else 0)
        s += flow((P[p], proc_y), (D[d], ty), tag, R, 0, at=at, both=tag not in ("F10", "F14"))

    s += text(40, 985, "All processes 2.0–5.0 also read D2 (validate session + CSRF token) and append to D7 (audit) — "
              "omitted for clarity.   Notation: rectangle = external entity · circle = process · open box = data store · "
              "red dashed = trust boundary.", 12, fill=GREY, anchor="start")
    return s + "</svg>\n"


if __name__ == "__main__":
    for name, fn in (("dfd-level0.svg", level0), ("dfd-level1.svg", level1)):
        with open(os.path.join(OUT, name), "w", encoding="utf-8") as fh:
            fh.write(fn())
        print("wrote", name)
