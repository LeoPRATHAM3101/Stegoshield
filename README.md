# 🛡️ StegoShield

Encrypted, password-keyed image steganography with built-in steganalysis.

## Security design
| Layer | What it does |
|---|---|
| zlib | compresses payload (more capacity, less structure) |
| scrypt (N=2^15) | password -> 64 bytes of key material (slow = brute-force resistant) |
| AES-256-GCM | encrypts + authenticates; wrong password or tampering is detected |
| Keyed permutation | bits scattered over the image in an order derived from the password (AES-CTR keystream sort) - no sequential "message strip" |
| No magic bytes | nothing in the file identifies it as stego; header = random salt + length |
| Lossless PNG output | LSBs survive (JPEG would destroy them) |

## Setup (macOS, VSCode)
```bash
cd stegoshield
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python make_sample.py          # makes samples/cover.png
pytest -q                      # run tests
```
In VSCode: Cmd+Shift+P -> "Python: Select Interpreter" -> pick `.venv`.

## Use
```bash
python -m stegoshield capacity samples/cover.png
python -m stegoshield hide samples/cover.png output/secret.png --text "meet at 9"
python -m stegoshield reveal output/secret.png
python -m stegoshield analyze samples/cover.png output/secret.png --plane output/lsb.png
streamlit run app.py           # GUI
```

## Limits (be honest in your report/viva)
- Any re-save as JPEG, resize, screenshot or social-media upload destroys the payload.
- Chi-square detects near-full-capacity embedding only; small payloads stay under it.
- Steganography hides *existence*; AES provides the *confidentiality*. Both matter.
- Educational/defensive use; don't use it to exfiltrate data you aren't authorised to move.

## Ideas to extend
DCT-domain (JPEG) embedding, RS / sample-pair steganalysis, adaptive embedding in noisy regions only, audio (WAV) support, error-correcting codes (Reed-Solomon), an ML detector (CNN on LSB residuals) - ties nicely into your AI/security portfolio.
