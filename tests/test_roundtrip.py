import numpy as np
import pytest
from PIL import Image

from stegoshield import analysis, stego


@pytest.fixture
def cover(tmp_path):
    rng = np.random.default_rng(1)
    arr = rng.integers(0, 256, (200, 200, 3), dtype=np.uint8)
    p = tmp_path / "cover.png"
    Image.fromarray(arr).save(p)
    return str(p)


def test_roundtrip_text(cover, tmp_path):
    out = str(tmp_path / "s.png")
    stego.hide(cover, out, b"top secret \xf0\x9f\x94\x90", "hunter2")
    assert stego.reveal(out, "hunter2") == b"top secret \xf0\x9f\x94\x90"


def test_roundtrip_binary(cover, tmp_path):
    out = str(tmp_path / "s.png")
    blob = bytes(range(256)) * 20
    stego.hide(cover, out, blob, "pw")
    assert stego.reveal(out, "pw") == blob


def test_wrong_password_fails(cover, tmp_path):
    out = str(tmp_path / "s.png")
    stego.hide(cover, out, b"hello", "right")
    with pytest.raises(ValueError):
        stego.reveal(out, "wrong")


def test_clean_image_has_no_data(cover):
    with pytest.raises(ValueError):
        stego.reveal(cover, "anything")


def test_capacity_error(cover, tmp_path):
    big = np.random.default_rng(2).bytes(40000)  # incompressible
    with pytest.raises(stego.CapacityError):
        stego.hide(cover, str(tmp_path / "s.png"), big, "pw")


def test_imperceptible(cover, tmp_path):
    out = str(tmp_path / "s.png")
    stego.hide(cover, out, b"x" * 500, "pw")
    assert analysis.mse_psnr(cover, out)["psnr_db"] > 50


def test_rgba_alpha_preserved(tmp_path):
    arr = np.random.default_rng(3).integers(0, 256, (80, 80, 4), dtype=np.uint8)
    src, out = str(tmp_path / "a.png"), str(tmp_path / "b.png")
    Image.fromarray(arr).save(src)
    stego.hide(src, out, b"alpha ok", "pw")
    assert stego.reveal(out, "pw") == b"alpha ok"
    assert (np.array(Image.open(out))[..., 3] == arr[..., 3]).all()
