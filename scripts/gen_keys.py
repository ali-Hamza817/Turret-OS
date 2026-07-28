"""
scripts/gen_keys.py
====================
Generate Ed25519 keypair for TURRET OS evidence signing.
Run once before first use:
  python scripts/gen_keys.py --out config/keys/
"""

from __future__ import annotations

import argparse
from pathlib import Path
from turret_evidence.signer import generate_keypair


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Ed25519 signing keypair")
    parser.add_argument("--out", default="config/keys/", help="Output directory")
    args = parser.parse_args()

    out_dir = Path(args.out)
    priv_path, pub_path = generate_keypair(out_dir)
    print(f"✅  Private key: {priv_path}")
    print(f"✅  Public key:  {pub_path}")
    print(f"\n⚠️   Keep {priv_path} SECRET. Set SIGNING_KEY_PATH={priv_path} in .env")


if __name__ == "__main__":
    main()
