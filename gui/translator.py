"""
Compatibility entry point for the GUI translation API.

New code should prefer importing from ``gui.i18n`` directly. This module keeps
the existing ``from .translator import ...`` call sites working while locale
resources and translation rules live in smaller, focused modules.
"""

from .i18n import (
    LanguageManager,
    lang_mgr,
    tr,
    translate_backend_output,
    translate_violation_reason,
)

__all__ = [
    "LanguageManager",
    "lang_mgr",
    "tr",
    "translate_backend_output",
    "translate_violation_reason",
]
