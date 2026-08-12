#!/usr/bin/env python3
"""Assemble captured PNG frames into the README's demo GIF.

Called by scripts/demo-gif.mjs; usable on its own against a directory of frames.

    python3 scripts/assemble-gif.py <frames-dir> <out.gif> [frame-ms]

Two settings do almost all the work on file size, and both are easy to get wrong:

  * ONE shared palette, quantized from a representative frame and applied to every other
    frame. Per-frame palettes make each frame carry its own colour table and defeat the
    inter-frame compression underneath.
  * dither=NONE. Dithering scatters pixels that would otherwise be identical between
    consecutive frames, which is exactly the redundancy the format compresses away. On a
    flat UI it also looks worse - the noise is visible on large areas of one colour.

Together they took a 19-second capture from 11 MB to 448 KB. disposal=1 (leave the
previous frame in place) completes it: the encoder then only stores what changed.
"""

import sys
import pathlib

try:
    from PIL import Image
except ImportError:  # pragma: no cover - the message is the whole point
    sys.exit(
        "Pillow is not installed for this interpreter.\n"
        f"  {sys.executable} -m pip install Pillow"
    )

# The README has always shown the GIF at this width; frames are captured at 2x and
# downsampled here, which is what keeps the text crisp.
TARGET_WIDTH = 900


def main() -> int:
    if len(sys.argv) < 3:
        return int(bool(sys.stderr.write(__doc__)))
    frames_dir = pathlib.Path(sys.argv[1])
    out = pathlib.Path(sys.argv[2])
    frame_ms = int(sys.argv[3]) if len(sys.argv) > 3 else 120

    paths = sorted(frames_dir.glob("*.png"))
    if not paths:
        sys.exit(f"no frames in {frames_dir}")

    images = []
    for p in paths:
        im = Image.open(p).convert("RGB")
        if im.width != TARGET_WIDTH:
            h = round(im.height * TARGET_WIDTH / im.width)
            im = im.resize((TARGET_WIDTH, h), Image.LANCZOS)
        images.append(im)

    # The palette comes from the LAST frame rather than the first: the trust page carries
    # the widest range of colour in the tour (the reliability diagram and the verdict
    # chips), so quantizing on it avoids banding there at no cost to the flatter screens.
    palette = images[-1].quantize(colors=256, method=Image.MEDIANCUT)
    quantized = [im.quantize(palette=palette, dither=Image.Dither.NONE) for im in images]

    quantized[0].save(
        out,
        save_all=True,
        append_images=quantized[1:],
        duration=frame_ms,
        loop=0,
        disposal=1,
        optimize=True,
    )
    size_kb = out.stat().st_size / 1024
    # Reopened rather than reporting len(quantized): optimize=True merges frames that are
    # identical to their predecessor, so the number written is not the number handed in,
    # and printing the input count would overstate what the file contains.
    with Image.open(out) as written:
        written_frames = getattr(written, "n_frames", len(quantized))
    print(f"  wrote {out} · {written_frames} frames · {images[0].size[0]}x{images[0].size[1]} · {size_kb:.0f} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
