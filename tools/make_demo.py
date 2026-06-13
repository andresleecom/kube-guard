#!/usr/bin/env python3
"""Generate assets/demo.gif: an animated terminal demo of kube-guard.

Pure Pillow; status icons are drawn (no emoji fonts -> no tofu).
Run:  pip install -r tools/requirements.txt  &&  python tools/make_demo.py

NOTE: this is a Windows-oriented authoring tool — it prefers the Consolas fonts
under C:\\Windows\\Fonts and falls back to DejaVu/the default font elsewhere, so
the GIF rendered on macOS/Linux will look slightly different. Only the maintainer
needs to run this; it is not part of the plugin runtime.
"""
import os
from PIL import Image, ImageDraw, ImageFont

W, H = 860, 500
BG = (13, 17, 23)
BAR = (22, 27, 34)
FG = (201, 209, 217)
DIM = (118, 126, 138)
WHITE = (236, 241, 246)
CYAN = (88, 166, 255)
GREEN = (63, 185, 80)
RED = (248, 95, 80)
AMBER = (230, 170, 60)
PURPLE = (197, 154, 255)

FONTS = r"C:\Windows\Fonts"


def load(name, size, fallback="DejaVuSansMono.ttf"):
    for cand in (name, fallback):
        p = os.path.join(FONTS, cand)
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    try:
        return ImageFont.truetype(name, size)
    except Exception:
        return ImageFont.load_default()


MONO = load("consola.ttf", 18)
MONOB = load("consolab.ttf", 18)
SMALL = load("consolab.ttf", 14)

LH = 26
PAD_X = 26
TOP = 58
frames, durs = [], []


def add(img, dur):
    frames.append(img)
    durs.append(dur)


def base(title):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 40], fill=BAR)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        cx = 24 + i * 22
        d.ellipse([cx - 6, 14, cx + 6, 26], fill=c)
    d.text((96, 12), title, font=SMALL, fill=DIM)
    return img, d


def icon_check(d, x, y):
    d.line([(x, y + 13), (x + 5, y + 18), (x + 13, y + 6)], fill=GREEN, width=2)


def icon_ask(d, x, y):
    d.ellipse([x, y + 4, x + 14, y + 18], outline=AMBER, width=2)
    d.text((x + 4, y + 2), "!", font=MONOB, fill=AMBER)


def icon_deny(d, x, y):
    cx, cy, r = x + 7, y + 11, 8
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=RED)
    d.rectangle([cx - 4, cy - 1, cx + 4, cy + 2], fill=(255, 255, 255))


def draw(d, lines):
    y = TOP
    ex, ey = PAD_X, TOP
    for segs in lines:
        x = PAD_X
        for text, color, bold in segs:
            f = MONOB if bold else MONO
            d.text((x, y), text, font=f, fill=color)
            x += int(d.textlength(text, font=f))
        ex, ey = x, y
        y += LH
    return ex, ey


def cursor(d, x, y):
    d.rectangle([x + 1, y + 4, x + 10, y + LH - 3], fill=(120, 162, 255))


def type_cmd(title, base_lines, text, ms=52, hold=550):
    prompt = [("$ ", CYAN, True)]
    i = 0
    n = len(text)
    while i <= n:
        line = list(prompt) + [(text[:i], WHITE, False)]
        img, d = base(title)
        ex, ey = draw(d, base_lines + [line])
        cursor(d, ex, ey)
        add(img, ms if i < n else hold)
        i += 2
    return base_lines + [list(prompt) + [(text, WHITE, False)]]


def reveal(title, base_lines, new_lines, icons=None, per=300, last_hold=1400):
    icons = icons or {}
    cur = list(base_lines)
    for k, nl in enumerate(new_lines):
        cur = cur + [nl]
        img, d = base(title)
        draw(d, cur)
        for idx, fn in icons.items():
            if idx <= len(cur) - 1:
                fn(d, PAD_X + 14, TOP + idx * LH)
        add(img, last_hold if k == len(new_lines) - 1 else per)
    return cur


TA = "claude code   kubectl is guarded by kube-guard"
n = 0
img, d = base(TA)
add(img, 600)

a = type_cmd(TA, [], "kubectl get pods")
base_idx = len(a)  # index where the next revealed line lands
a = reveal(TA, a, [
    [("   ", FG, False), ("allowed", GREEN, True), ("  READ", DIM, False)],
    [("   web-7d9c   1/1   Running", DIM, False)],
    [("", FG, False)],
], icons={base_idx: icon_check}, per=260, last_hold=600)

a = type_cmd(TA, a, "kubectl apply -f deploy.yaml")
idx = len(a)
a = reveal(TA, a, [
    [("   ", FG, False), ("ask", AMBER, True), ("  WRITE - confirm before applying", DIM, False)],
    [("", FG, False)],
], icons={idx: icon_ask}, per=260, last_hold=700)

a = type_cmd(TA, a, "kubectl delete namespace prod")
idx = len(a)
a = reveal(TA, a, [
    [("   ", FG, False), ("DENIED", RED, True), ("  DESTRUCTIVE on protected context 'prod'", FG, False)],
    [("   logged to .claude/kube-guard/audit.jsonl", DIM, False)],
], icons={idx: icon_deny}, per=320, last_hold=2600)

# Title card
img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)
big = load("consolab.ttf", 40)
sub = load("consola.ttf", 20)
t1 = "kube-guard"
t2 = "kubectl for your agent, with a seatbelt"
d.text(((W - d.textlength(t1, font=big)) / 2, H / 2 - 56), t1, font=big, fill=PURPLE)
d.text(((W - d.textlength(t2, font=sub)) / 2, H / 2 + 4), t2, font=sub, fill=DIM)
add(img, 2600)

out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets", "demo.gif")
os.makedirs(os.path.dirname(out), exist_ok=True)
frames[0].save(out, save_all=True, append_images=frames[1:], duration=durs, loop=0, optimize=True, disposal=2)
print(f"wrote {out}")
print(f"frames={len(frames)}  duration={sum(durs)/1000:.1f}s  size={os.path.getsize(out)/1024:.0f} KB")
