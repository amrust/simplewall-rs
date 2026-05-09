#!/usr/bin/env python3
"""
Generate a new amwall locale file from en.toml.

Usage:
    python locales/gen_locale.py <lang_code> <native_name>

Example:
    python locales/gen_locale.py bg "Български"

This creates locales/<lang_code>.toml as a copy of en.toml with a
translated header comment. The values are left in English — a human
or LLM translates them afterward.

For LLM-assisted translation, feed the generated file along with
this prompt:

    Translate all values in this TOML file to <language>.
    Rules:
    - Keep all TOML keys exactly the same
    - Keep %{variable} placeholders verbatim
    - Keep keyboard shortcuts as-is (Ctrl+P, F5, \\tCtrl+O, etc.)
    - Keep technical terms in English: TCP, UDP, ICMP, IPv4, IPv6,
      SHA-256, WFP, UAC, XML, UWP, loopback, amwall, simplewall,
      GitHub, profile.xml
    - Place & accelerator on an appropriate character (CJK: remove &)
    - Use \\" for embedded quotes — do NOT use typographic quotes
    - Keep \\n escape sequences as-is
    - Keep bullet character as-is
    - Keep the triple-quote multi-line format for wizard.body
    - Protocol/action names (TCP, UDP, Allow, Block) stay as-is
      in the [protocol]/[version]/[direction] sections

After translating, add a display-name entry in
src/gui/settings_dialog.rs -> locale_display_name():
    "<code>" => "<NativeName>",

Then rebuild: cargo build
The build will fail at compile time if the TOML is malformed.

Validating without a full build (Python 3.11+):
    python -c "import tomllib; tomllib.load(open('locales/<code>.toml','rb'))"
"""

import shutil
import sys
from pathlib import Path


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <lang_code> <native_name>")
        print(f'Example: {sys.argv[0]} bg "Български"')
        sys.exit(1)

    code = sys.argv[1]
    native = sys.argv[2]
    locales_dir = Path(__file__).parent
    src = locales_dir / "en.toml"
    dst = locales_dir / f"{code}.toml"

    if not src.exists():
        print(f"Error: {src} not found")
        sys.exit(1)

    if dst.exists():
        print(f"Error: {dst} already exists")
        sys.exit(1)

    content = src.read_text(encoding="utf-8")

    # Replace the English header comment
    old_header = "# amwall — English locale (default fallback).\n# Add new languages by copying this file to e.g. locales/de.toml\n# and translating the values. rust-i18n embeds all locales at\n# compile time; set the active locale with rust_i18n::set_locale()."
    new_header = f"# amwall — {native} ({code})\n# Translated from en.toml. See gen_locale.py for instructions."
    content = content.replace(old_header, new_header, 1)

    dst.write_text(content, encoding="utf-8")
    print(f"Created {dst}")
    print(f"Next: translate values, then add to locale_display_name():")
    print(f'    "{code}" => "{native}",')


if __name__ == "__main__":
    main()
