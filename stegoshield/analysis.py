"""Quality metrics + steganalysis (what an attacker/defender would run)."""
import numpy as np
from PIL import Image
from scipy.stats import chi2

from .stego import load_image


def mse_psnr(cover_path: str, stego_path: str) -> dict:
    a = load_image(cover_path)[..., :3].astype(np.float64)
    b = load_image(stego_path)[..., :3].astype(np.float64)
    if a.shape != b.shape:
        raise ValueError("Images must have the same dimensions.")
    mse = float(np.mean((a - b) ** 2))
    psnr = float("inf") if mse == 0 else float(10 * np.log10(255**2 / mse))
    changed = int(np.count_nonzero(a != b))
    return {
        "mse": round(mse, 6),
        "psnr_db": psnr if psnr == float("inf") else round(psnr, 2),
        "values_changed": changed,
        "pct_changed": round(100 * changed / a.size, 4),
    }


def chi_square_lsb(path: str) -> dict:
    """Westfeld-Pfitzner chi-square attack on pairs of values (2k, 2k+1).

    Full-capacity LSB embedding equalises each pair's frequencies. A p-value
    near 1.0 => pairs look equalised => likely embedded. Low p => likely clean.
    Sparse (small-message) embedding stays below this test's sensitivity.
    """
    flat = load_image(path)[..., :3].reshape(-1)
    hist = np.bincount(flat, minlength=256).astype(np.float64)
    even, odd = hist[0::2], hist[1::2]
    expected = (even + odd) / 2
    mask = expected > 5
    if mask.sum() < 2:
        return {"chi2": None, "p_value": None, "verdict": "not enough data"}
    stat = float(np.sum((even[mask] - expected[mask]) ** 2 / expected[mask]))
    dof = int(mask.sum() - 1)
    p = float(chi2.sf(stat, dof))
    verdict = (
        "SUSPICIOUS (pairs equalised)" if p > 0.95
        else "possible" if p > 0.5
        else "looks clean"
    )
    return {"chi2": round(stat, 2), "dof": dof, "p_value": round(p, 4), "verdict": verdict}


def lsb_plane(path: str, out_path: str) -> str:
    """Render the LSB plane as a black/white image (visual steganalysis).
    Natural images show structure; saturated random noise suggests embedding."""
    flat = load_image(path)[..., :3]
    plane = ((flat & 1) * 255).astype(np.uint8)
    Image.fromarray(plane).save(out_path)
    return out_path
