"""Generate Excalidraw-style architecture PNG for README."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "architecture.png"

W, H = 1280, 420
BG = "#ffffff"
STROKE = "#1e1e1e"

BOXES = [
    (40, 150, 200, 72, "#ffd8a8", "External Data", "dataset/ + data/*.csv"),
    (280, 150, 170, 72, "#d0bfff", "data_loader", "paths + resolver"),
    (490, 150, 190, 72, "#a5d8ff", "detector + taint", "scan_workflow"),
    (720, 150, 170, 72, "#b2f2bb", "patcher", "env-wrap diff"),
    (930, 150, 150, 72, "#b2f2bb", "predict", "CSV rows"),
    (1110, 150, 130, 72, "#ffd8a8", "Kaggle", "submission.csv"),
    (490, 40, 260, 58, "#fff3bf", "CLI main.py", "scan | eval | patch | predict"),
    (720, 280, 200, 58, "#ffe8cc", "OpenRouter LLM", "optional assist"),
    (280, 280, 180, 58, "#e9ecef", "evaluate", "TP / FP / FN"),
]

ARROWS = [
    ((240, 186), (280, 186)),
    ((450, 186), (490, 186)),
    ((680, 186), (720, 186)),
    ((890, 186), (930, 186)),
    ((1080, 186), (1110, 186)),
    ((620, 98), (575, 150)),
    ((820, 280), (575, 222), True),
    ((370, 280), (370, 222)),
]


def _font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "C:/Windows/Fonts/segoeui.ttf",
        "C:/Windows/Fonts/arial.ttf",
    ]
    if bold:
        candidates = [
            "C:/Windows/Fonts/seguisb.ttf",
            "C:/Windows/Fonts/arialbd.ttf",
            *candidates,
        ]
    for path in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _rounded_rect(draw: ImageDraw.ImageDraw, xy: tuple[int, int, int, int], fill: str, outline: str) -> None:
    x1, y1, x2, y2 = xy
    draw.rounded_rectangle((x1, y1, x2, y2), radius=14, fill=fill, outline=outline, width=2)


def _arrow(draw: ImageDraw.ImageDraw, start: tuple[int, int], end: tuple[int, int], dashed: bool = False) -> None:
    if dashed:
        steps = 12
        for i in range(steps):
            if i % 2 == 0:
                t0, t1 = i / steps, (i + 1) / steps
                p0 = (start[0] + (end[0] - start[0]) * t0, start[1] + (end[1] - start[1]) * t0)
                p1 = (start[0] + (end[0] - start[0]) * t1, start[1] + (end[1] - start[1]) * t1)
                draw.line([p0, p1], fill=STROKE, width=2)
    else:
        draw.line([start, end], fill=STROKE, width=2)
    # arrow head
    import math

    angle = math.atan2(end[1] - start[1], end[0] - start[0])
    size = 10
    left = (
        end[0] - size * math.cos(angle - math.pi / 6),
        end[1] - size * math.sin(angle - math.pi / 6),
    )
    right = (
        end[0] - size * math.cos(angle + math.pi / 6),
        end[1] - size * math.sin(angle + math.pi / 6),
    )
    draw.polygon([end, left, right], fill=STROKE)


def main() -> None:
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)
    title_font = _font(22, bold=True)
    label_font = _font(15, bold=True)
    sub_font = _font(12)

    draw.text((40, 24), "Challenge 02 — Pipeline Architecture", fill=STROKE, font=title_font)
    draw.text((40, 52), "Rules-first core with optional OpenRouter augmentation", fill="#495057", font=sub_font)

    for x, y, w, h, color, title, subtitle in BOXES:
        _rounded_rect(draw, (x, y, x + w, y + h), color, STROKE)
        draw.text((x + 12, y + 14), title, fill=STROKE, font=label_font)
        draw.text((x + 12, y + 38), subtitle, fill="#343a40", font=sub_font)

    for item in ARROWS:
        start, end = item[0], item[1]
        dashed = item[2] if len(item) > 2 else False
        _arrow(draw, start, end, dashed=dashed)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    img.save(OUT, format="PNG")
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
