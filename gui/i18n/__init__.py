from .manager import LanguageManager, lang_mgr, tr
from .backend_patterns import translate_backend_output, translate_violation_reason

__all__ = [
    "LanguageManager",
    "lang_mgr",
    "tr",
    "translate_backend_output",
    "translate_violation_reason",
]
