"""Streamlit GUI:  streamlit run app.py"""
import os
import tempfile

import streamlit as st
from PIL import Image

from stegoshield import analysis, stego

st.set_page_config(page_title="StegoShield", page_icon="🛡️", layout="centered")
st.title("🛡️ StegoShield")
st.caption("Encrypted (AES-256-GCM) + password-keyed LSB steganography with built-in steganalysis")


def to_tmp(uploaded) -> str:
    suffix = os.path.splitext(uploaded.name)[1] or ".png"
    f = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    f.write(uploaded.getvalue())
    f.close()
    return f.name


tab_hide, tab_reveal, tab_analyze = st.tabs(["Hide", "Reveal", "Analyze"])

with tab_hide:
    cover = st.file_uploader("Cover image (PNG/BMP recommended)", type=["png", "bmp", "jpg", "jpeg"], key="c")
    mode = st.radio("Payload", ["Text", "File"], horizontal=True)
    text = st.text_area("Secret message") if mode == "Text" else None
    file = st.file_uploader("Secret file", key="f") if mode == "File" else None
    pw = st.text_input("Password", type="password", key="hp")
    if cover:
        cap = stego.capacity(stego.load_image(to_tmp(cover)))
        st.info(f"Capacity ≈ {cap['approx_max_message_bytes']:,} bytes")
    if st.button("Hide", type="primary"):
        if not (cover and pw and (text or file)):
            st.error("Need a cover image, a payload and a password.")
        else:
            try:
                cp = to_tmp(cover)
                out = os.path.join(tempfile.mkdtemp(), "stego.png")
                data = text.encode() if mode == "Text" else file.getvalue()
                info = stego.hide(cp, out, data, pw)
                m = analysis.mse_psnr(cp, out)
                st.success(f"Hidden {info['message_bytes']:,} bytes. PSNR {m['psnr_db']} dB, "
                           f"{m['pct_changed']}% of values changed.")
                st.image(Image.open(out), caption="Stego image")
                st.download_button("Download stego.png", open(out, "rb").read(), "stego.png", "image/png")
            except Exception as e:
                st.error(str(e))

with tab_reveal:
    s = st.file_uploader("Stego image (PNG)", type=["png", "bmp"], key="s")
    pw2 = st.text_input("Password", type="password", key="rp")
    if st.button("Reveal"):
        if not (s and pw2):
            st.error("Need the stego image and password.")
        else:
            try:
                data = stego.reveal(to_tmp(s), pw2)
                try:
                    st.code(data.decode("utf-8"))
                except UnicodeDecodeError:
                    st.download_button("Download recovered file", data, "recovered.bin")
            except Exception as e:
                st.error(str(e))

with tab_analyze:
    a = st.file_uploader("Image to analyze", type=["png", "bmp", "jpg", "jpeg"], key="a")
    b = st.file_uploader("Optional: stego version to compare", type=["png", "bmp"], key="b")
    if a and st.button("Run analysis"):
        ap = to_tmp(a)
        tgt = to_tmp(b) if b else ap
        if b:
            st.json(analysis.mse_psnr(ap, tgt))
        st.json(analysis.chi_square_lsb(tgt))
        plane = os.path.join(tempfile.mkdtemp(), "lsb.png")
        analysis.lsb_plane(tgt, plane)
        st.image(plane, caption="LSB plane (structure = natural, uniform noise = suspicious)")
