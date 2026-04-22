import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib import error, request

from PyQt6.QtGui import QFont, QFontDatabase

APP_NAME = "NetworkAnalyzer"
APP_VERSION = "2.2"
APP_VERSION_DISPLAY = "2.2"
APP_RELEASE_MONTH = "2026-04"
GITHUB_REPOSITORY = "Na-Bian/Network-Traffic-Analysis-Anomaly-Detection-System"
GITHUB_REPOSITORY_URL = f"https://github.com/{GITHUB_REPOSITORY}"
GITHUB_RELEASES_URL = f"{GITHUB_REPOSITORY_URL}/releases"
GITHUB_LATEST_RELEASE_API = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/releases/latest"

DEFAULT_UI_FONT_FAMILIES = [
    "Microsoft YaHei UI",
    "Microsoft YaHei",
    "Noto Sans SC",
    "Segoe UI",
]


def _settings_root() -> Path:
    config_root = os.environ.get("APPDATA")
    if config_root:
        return Path(config_root) / APP_NAME
    return Path.home() / f".{APP_NAME.lower()}"


def _settings_path() -> Path:
    return _settings_root() / "app_settings.json"


@dataclass
class AppPreferences:
    ui_font_family: str = ""


def load_app_preferences() -> AppPreferences:
    path = _settings_path()
    if not path.exists():
        return AppPreferences()

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return AppPreferences()

    return AppPreferences(
        ui_font_family=str(data.get("ui_font_family") or "").strip(),
    )


def save_app_preferences(preferences: AppPreferences) -> None:
    path = _settings_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(asdict(preferences), f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def installed_font_families() -> set[str]:
    return {family.strip() for family in QFontDatabase.families() if family.strip()}


def first_available_font_family(candidates: list[str]) -> str:
    installed = installed_font_families()
    for family in candidates:
        if family in installed:
            return family
    return candidates[0] if candidates else ""


def build_ui_font_families(preferred_family: str | None) -> list[str]:
    families: list[str] = []
    installed = installed_font_families()
    preferred = str(preferred_family or "").strip()
    if preferred and preferred in installed:
        families.append(preferred)

    for family in DEFAULT_UI_FONT_FAMILIES:
        if family in installed and family not in families:
            families.append(family)

    if not families:
        families.append(first_available_font_family(DEFAULT_UI_FONT_FAMILIES))

    return families


def ui_font_choices() -> list[str]:
    installed = installed_font_families()
    prioritized = [family for family in DEFAULT_UI_FONT_FAMILIES if family in installed]
    remaining = sorted(installed.difference(prioritized), key=str.casefold)
    return prioritized + remaining


def build_ui_font(preferred_family: str | None, point_size: int = 10) -> QFont:
    families = build_ui_font_families(preferred_family)
    font = QFont()
    if hasattr(font, "setFamilies"):
        font.setFamilies(families)
    else:
        font.setFamily(families[0])
    font.setPointSize(point_size)
    return font


def font_supports_chinese(family: str | None) -> bool:
    family_name = str(family or "").strip()
    if not family_name:
        return True

    try:
        writing_systems = set(QFontDatabase.writingSystems(family_name))
    except Exception:
        return False

    chinese_systems = {
        getattr(QFontDatabase.WritingSystem, "SimplifiedChinese", None),
        getattr(QFontDatabase.WritingSystem, "TraditionalChinese", None),
    }
    return any(system in writing_systems for system in chinese_systems if system is not None)


def normalize_release_version(value: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return re.sub(r"^[vV]", "", text)


def compare_release_versions(current: str, latest: str) -> int:
    def version_key(value: str) -> tuple[list[int], bool]:
        raw = normalize_release_version(value)
        numbers = [int(part) for part in re.findall(r"\d+", raw)]
        prerelease = bool(re.search(r"[A-Za-z]", raw))
        return numbers, prerelease

    current_numbers, current_prerelease = version_key(current)
    latest_numbers, latest_prerelease = version_key(latest)
    max_len = max(len(current_numbers), len(latest_numbers), 1)

    current_numbers.extend([0] * (max_len - len(current_numbers)))
    latest_numbers.extend([0] * (max_len - len(latest_numbers)))

    if current_numbers < latest_numbers:
        return -1
    if current_numbers > latest_numbers:
        return 1
    if current_prerelease and not latest_prerelease:
        return -1
    if latest_prerelease and not current_prerelease:
        return 1
    return 0


def format_release_date(value: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).strftime("%Y-%m-%d")
    except ValueError:
        return text


def check_latest_release(timeout: float = 6.0) -> dict[str, Any]:
    req = request.Request(
        GITHUB_LATEST_RELEASE_API,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"{APP_NAME}/{APP_VERSION}",
        },
        method="GET",
    )

    try:
        with request.urlopen(req, timeout=timeout) as resp:
            payload = json.load(resp)
    except error.HTTPError as exc:
        if exc.code == 404:
            return {
                "status": "no_release",
                "current_version": APP_VERSION,
                "releases_url": GITHUB_RELEASES_URL,
            }
        raise RuntimeError(f"GitHub API HTTP {exc.code}")
    except error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise RuntimeError(f"无法连接 GitHub：{reason}")
    except Exception as exc:
        raise RuntimeError(str(exc))

    latest_version = normalize_release_version(str(payload.get("tag_name") or payload.get("name") or "").strip())
    release_name = normalize_release_version(str(payload.get("name") or payload.get("tag_name") or "").strip())
    html_url = str(payload.get("html_url") or GITHUB_RELEASES_URL).strip()
    published_at = format_release_date(payload.get("published_at"))
    comparison = compare_release_versions(APP_VERSION, latest_version)

    return {
        "status": "update_available" if comparison < 0 else "up_to_date",
        "current_version": APP_VERSION,
        "latest_version": latest_version or APP_VERSION,
        "release_name": release_name or latest_version or APP_VERSION,
        "published_at": published_at,
        "html_url": html_url,
        "releases_url": GITHUB_RELEASES_URL,
        "raw": payload,
    }
