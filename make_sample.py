"""Generate a textured demo cover image (no internet needed): python make_sample.py"""
import numpy as np
from PIL import Image

rng = np.random.default_rng(7)
h, w = 720, 1080
y, x = np.mgrid[0:h, 0:w]
r = 128 + 100 * np.sin(x / 90) * np.cos(y / 70)
g = 128 + 100 * np.sin((x + y) / 120)
b = 128 + 100 * np.cos(x / 60 - y / 100)
img = np.stack([r, g, b], -1) + rng.normal(0, 6, (h, w, 3))  # sensor-like noise
Image.fromarray(np.clip(img, 0, 255).astype(np.uint8)).save("samples/cover.png")
print("samples/cover.png created")
