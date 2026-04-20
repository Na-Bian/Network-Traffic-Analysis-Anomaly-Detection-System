import json
import os
from pathlib import Path

from PyQt6.QtCore import QObject, pyqtSignal

DEFAULT_LANGUAGE = "zh_CN"


def _project_root():
    return Path(__file__).resolve().parents[2]


def _default_config_path():
    config_root = os.environ.get("APPDATA")
    if config_root:
        return Path(config_root) / "NetworkAnalyzer" / "lang_config.json"
    return Path.home() / ".network_analyzer" / "lang_config.json"


class LanguageManager(QObject):
    """Load locale resources and notify the UI when language changes."""

    language_changed = pyqtSignal()

    def __init__(self, config_file=None, locales_dir=None):
        super().__init__()
        self.locales_dir = Path(locales_dir) if locales_dir else _project_root() / "gui" / "i18n" / "locales"
        self.config_file = Path(config_file) if config_file else _default_config_path()
        self.current_lang = DEFAULT_LANGUAGE
        self._translations = {}
        self._load_locales()
        self.load_config()

    def _load_locales(self):
        self._translations.clear()
        if not self.locales_dir.exists():
            return

        for path in sorted(self.locales_dir.glob("*.json")):
            try:
                with path.open("r", encoding="utf-8") as f:
                    self._translations[path.stem] = json.load(f)
            except Exception as e:
                print(f"加载语言文件失败 {path}: {e}")

    @property
    def available_languages(self):
        return set(self._translations)

    def load_config(self):
        config_file = self.config_file
        legacy_config = _project_root() / "lang_config.json"
        if not config_file.exists() and legacy_config.exists():
            config_file = legacy_config

        if not config_file.exists():
            return

        try:
            with config_file.open("r", encoding="utf-8") as f:
                lang = json.load(f).get("language", DEFAULT_LANGUAGE)
            if lang in self.available_languages:
                self.current_lang = lang
        except Exception as e:
            print(f"读取语言配置失败: {e}")

    def save_config(self):
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with self.config_file.open("w", encoding="utf-8") as f:
                json.dump({"language": self.current_lang}, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"保存语言配置失败: {e}")

    def set_language(self, lang):
        if lang in self.available_languages and lang != self.current_lang:
            self.current_lang = lang
            self.save_config()
            self.language_changed.emit()

    def tr(self, key, default=None):
        current = self._translations.get(self.current_lang, {})
        if key in current:
            return current[key]

        fallback = self._translations.get(DEFAULT_LANGUAGE, {})
        return fallback.get(key, default or key)


lang_mgr = LanguageManager()


def tr(key, default=None):
    return lang_mgr.tr(key, default)
