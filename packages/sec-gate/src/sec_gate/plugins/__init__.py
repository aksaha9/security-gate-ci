"""Scanner plugin registry and built-in plugin registrations."""

from sec_gate.plugins.base import (
    BaseScannerPlugin,
    PluginRegistry,
    default_registry,
    register_plugin,
)
from sec_gate.plugins.injection import InjectionPlugin
from sec_gate.plugins.kingfisher import KingfisherPlugin

default_registry.discover_entry_points()

__all__ = [
    "BaseScannerPlugin",
    "InjectionPlugin",
    "KingfisherPlugin",
    "PluginRegistry",
    "default_registry",
    "register_plugin",
]
