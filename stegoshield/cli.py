"""StegoShield command line interface.

Examples (run from the project root):
  python -m stegoshield capacity samples/cover.png
  python -m stegoshield hide    samples/cover.png output/secret.png --text "meet at 9"
  python -m stegoshield hide    samples/cover.png output/secret.png --file notes.pdf
  python -m stegoshield reveal  output/secret.png
  python -m stegoshield reveal  output/secret.png --out recovered.pdf
  python -m stegoshield analyze samples/cover.png output/secret.png
"""
import argparse
import getpass
import sys

from . import analysis, stego


def _password(args, confirm=False) -> str:
    if args.password:
        return args.password
    pw = getpass.getpass("Password: ")
    if confirm and pw != getpass.getpass("Confirm password: "):
        sys.exit("Passwords do not match.")
    return pw


def cmd_capacity(args):
    info = stego.capacity(stego.load_image(args.image))
    print(f"Channel values : {info['channel_values']:,}")
    print(f"Max payload    : {info['max_blob_bytes']:,} bytes (encrypted blob)")
    print(f"~Max message   : {info['approx_max_message_bytes']:,} bytes")


def cmd_hide(args):
    if bool(args.text) == bool(args.file):
        sys.exit("Provide exactly one of --text or --file.")
    data = args.text.encode("utf-8") if args.text else open(args.file, "rb").read()
    info = stego.hide(args.cover, args.output, data, _password(args, confirm=True))
    print(f"Hidden {info['message_bytes']:,} bytes -> {info['output']}")
    print(f"Image utilisation: {info['utilisation_pct']}%")
    m = analysis.mse_psnr(args.cover, info["output"])
    print(f"PSNR: {m['psnr_db']} dB | values changed: {m['pct_changed']}%")


def cmd_reveal(args):
    data = stego.reveal(args.stego, _password(args))
    if args.out:
        open(args.out, "wb").write(data)
        print(f"Recovered {len(data):,} bytes -> {args.out}")
    else:
        try:
            print(data.decode("utf-8"))
        except UnicodeDecodeError:
            sys.exit("Payload is binary; use --out <file> to save it.")


def cmd_analyze(args):
    if args.stego:
        m = analysis.mse_psnr(args.image, args.stego)
        print(f"Cover vs stego -> PSNR {m['psnr_db']} dB, MSE {m['mse']}, "
              f"{m['pct_changed']}% of values changed")
    target = args.stego or args.image
    c = analysis.chi_square_lsb(target)
    print(f"Chi-square on {target}: chi2={c['chi2']} p={c['p_value']} -> {c['verdict']}")
    if args.plane:
        print("LSB plane saved:", analysis.lsb_plane(target, args.plane))


def main(argv=None):
    p = argparse.ArgumentParser(prog="stegoshield", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("capacity", help="how much can this image hold")
    s.add_argument("image"); s.set_defaults(fn=cmd_capacity)

    s = sub.add_parser("hide", help="encrypt + embed a message/file")
    s.add_argument("cover"); s.add_argument("output")
    s.add_argument("--text"); s.add_argument("--file"); s.add_argument("--password")
    s.set_defaults(fn=cmd_hide)

    s = sub.add_parser("reveal", help="extract + decrypt")
    s.add_argument("stego"); s.add_argument("--out"); s.add_argument("--password")
    s.set_defaults(fn=cmd_reveal)

    s = sub.add_parser("analyze", help="PSNR + chi-square steganalysis")
    s.add_argument("image", help="cover (or any) image")
    s.add_argument("stego", nargs="?", help="stego image to compare against cover")
    s.add_argument("--plane", help="save LSB-plane visualisation to this PNG")
    s.set_defaults(fn=cmd_analyze)

    args = p.parse_args(argv)
    try:
        args.fn(args)
    except (ValueError, FileNotFoundError, stego.CapacityError) as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    main()
