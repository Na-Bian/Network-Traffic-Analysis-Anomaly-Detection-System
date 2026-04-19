import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCALES_DIR = ROOT / "gui" / "i18n" / "locales"
REFERENCE_LANG = "zh_CN"


def load_locale(path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def placeholder_count(value):
    return len(re.findall(r"(?<!\{)\{\}(?!\})", value))


def main():
    locale_paths = sorted(LOCALES_DIR.glob("*.json"))
    if not locale_paths:
        print(f"No locale files found in {LOCALES_DIR}")
        return 1

    locales = {path.stem: load_locale(path) for path in locale_paths}
    if REFERENCE_LANG not in locales:
        print(f"Reference locale missing: {REFERENCE_LANG}")
        return 1

    reference_keys = set(locales[REFERENCE_LANG])
    failed = False

    for lang, messages in locales.items():
        keys = set(messages)
        missing = sorted(reference_keys - keys)
        extra = sorted(keys - reference_keys)

        if missing:
            failed = True
            print(f"[{lang}] missing keys:")
            for key in missing:
                print(f"  - {key}")

        if extra:
            failed = True
            print(f"[{lang}] extra keys:")
            for key in extra:
                print(f"  - {key}")

        for key in sorted(reference_keys & keys):
            expected = placeholder_count(str(locales[REFERENCE_LANG][key]))
            actual = placeholder_count(str(messages[key]))
            if expected != actual:
                failed = True
                print(
                    f"[{lang}] placeholder mismatch for {key}: "
                    f"expected {expected}, got {actual}"
                )

    if failed:
        return 1

    print(f"i18n check passed: {len(locales)} locales, {len(reference_keys)} keys")
    return 0


if __name__ == "__main__":
    sys.exit(main())
