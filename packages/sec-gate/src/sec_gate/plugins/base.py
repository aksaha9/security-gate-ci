"""Abstract scanner plugin contract and runtime plugin registry."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, ClassVar

from sec_gate.models import FindingCategory, PluginResult

logger = logging.getLogger(__name__)


class BaseScannerPlugin(ABC):
    """Contract that every sec-gate scanner plugin must implement."""

    name: ClassVar[str]
    description: ClassVar[str] = ""
    category: ClassVar[FindingCategory] = FindingCategory.OTHER
    version: ClassVar[str] = "0.1.0"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        self.raw_options: dict[str, Any] = dict(options or {})

    def is_available(self) -> tuple[bool, str | None]:
        """Return ``(True, None)`` if the plugin can execute in this environment."""
        return True, None

    @abstractmethod
    def scan(self, target: Path) -> PluginResult:
        """Scan ``target`` and return normalized findings wrapped in a ``PluginResult``."""


class PluginRegistry:
    """Thread-safe registry for built-in and externally registered plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, type[BaseScannerPlugin]] = {}

    def register(self, plugin_cls: type[BaseScannerPlugin]) -> type[BaseScannerPlugin]:
        """Register a ``BaseScannerPlugin`` subclass by its ``name`` attribute.

        Can be used directly or as a class decorator ``@registry.register``.
        """
        if not issubclass(plugin_cls, BaseScannerPlugin):
            raise TypeError(f"{plugin_cls!r} must subclass BaseScannerPlugin")
        plugin_name = getattr(plugin_cls, "name", "").strip()
        if not plugin_name:
            raise ValueError(f"Plugin class {plugin_cls.__name__} must define a non-empty 'name'")
        self._plugins[plugin_name] = plugin_cls
        return plugin_cls

    def unregister(self, name: str) -> None:
        """Remove a plugin by name if present."""
        self._plugins.pop(name, None)

    def get(self, name: str) -> type[BaseScannerPlugin]:
        """Return the plugin class registered for ``name`` or raise ``KeyError``."""
        if name not in self._plugins:
            available = ", ".join(sorted(self._plugins)) or "<none>"
            raise KeyError(f"Unknown plugin {name!r}. Registered plugins: {available}")
        return self._plugins[name]

    def create(self, name: str, options: dict[str, Any] | None = None) -> BaseScannerPlugin:
        """Instantiate a registered plugin with its configuration options."""
        plugin_cls = self.get(name)
        return plugin_cls(options=options)

    def names(self) -> list[str]:
        """Return sorted list of registered plugin names."""
        return sorted(self._plugins)

    def list_plugins(self) -> list[type[BaseScannerPlugin]]:
        """Return registered plugin classes sorted by plugin name."""
        return [self._plugins[name] for name in self.names()]

    def discover_entry_points(self, group: str = "sec_gate.plugins") -> list[str]:
        """Load external plugins advertised via Python package entry points."""
        loaded: list[str] = []
        for ep in entry_points(group=group):
            try:
                plugin_cls = ep.load()
                if isinstance(plugin_cls, type) and issubclass(plugin_cls, BaseScannerPlugin):
                    plugin_name = getattr(plugin_cls, "name", ep.name)
                    if plugin_name not in self._plugins:
                        self.register(plugin_cls)
                        loaded.append(plugin_name)
            except Exception as exc:  # pragma: no cover - defensive around external entry points
                logger.warning("Failed to load plugin entry point %s: %s", ep.name, exc)
        return loaded

    def clone(self) -> PluginRegistry:
        """Return a shallow copy of this registry (useful for isolated tests)."""
        copied = PluginRegistry()
        copied._plugins = dict(self._plugins)
        return copied


default_registry = PluginRegistry()
register_plugin: Callable[[type[BaseScannerPlugin]], type[BaseScannerPlugin]] = (
    default_registry.register
)
