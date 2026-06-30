"""Invariant rule pack loader.

Rules are plain Python modules exposing a module-level ``RULES`` list. This
lets operators express arbitrary procedural matchers (not just the declarative
``ToxicFlowRule`` / ``LoopRule`` shapes) while keeping the pack versionable in
Git alongside the rest of the manifests.

Loading is by import path or filesystem path:

* ``INVARIANT_RULES_PATH=/etc/guardrails/rules.policy`` — a ``.py`` file on
  disk, hot-reloadable via ``SIGHUP`` / ``inotify``.
* ``INVARIANT_RULES_MODULE=guardrails.rules.default`` — a dotted import path
  (useful for tests / bundled packs).

If neither is set, :mod:`guardrails.rules.default` is used.
"""

from __future__ import annotations

import importlib
import os
import threading

from ..invariant import Rule, ToxicFlowRule


def _validate(rules: object) -> list[Rule]:
    if not isinstance(rules, (list, tuple)):
        raise TypeError(f"RULES must be a list/tuple, got {type(rules)!r}")
    normalised: list[Rule] = []
    for i, r in enumerate(rules):
        if isinstance(r, ToxicFlowRule):
            normalised.append(r)
            continue
        # Duck-type: any object with name + match(trace)->Optional[str].
        if hasattr(r, "name") and callable(getattr(r, "match", None)):
            normalised.append(r)  # type: ignore[arg-type]
            continue
        raise TypeError(f"RULES[{i}] is not a valid rule: {r!r}")
    return normalised


def _load_from_path(path: str) -> list[Rule]:
    # Read the source fresh from disk and exec it in an isolated namespace on
    # every call. We deliberately AVOID importlib's module-loader machinery
    # (SourceFileLoader / spec_from_file_location) here for two reasons:
    #
    #   1. SourceFileLoader persists a __pycache__/<name>.cpython-XY.pyc next
    #      to the source and validates it by comparing the stored source mtime
    #      to the on-disk source mtime. mtime has 1-second resolution on many
    #      filesystems (including GitHub Actions runners), so a rule pack
    #      rewritten within the same second is served from the STALE .pyc —
    #      which breaks hot-reload (SIGHUP) semantics and is exactly the bug
    #      that made test_rule_pack_reload flaky in CI.
    #
    #   2. spec_from_file_location refuses to invent a loader for extensions
    #      it does not recognise (e.g. ``rules.policy``), requiring extra
    #      plumbing. Reading + compile() + exec() works for any extension.
    #
    # Reading the file fresh on every load is the correct contract for a
    # policy/config file: the on-disk bytes are the source of truth, always.
    #
    # We open with os.open() + os.read() rather than the buffered open() +
    # fh.read() to bypass Python's userspace I/O buffering layer entirely.
    # On some CI filesystems (overlayfs with writeback) a write_text() can
    # be held in the page cache such that a buffered read() immediately
    # afterward returns the OLD content; going straight to the raw fd forces
    # a real read syscall that sees the post-write bytes.
    fd = os.open(path, os.O_RDONLY)
    try:
        source = b""
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            source += chunk
    finally:
        os.close(fd)
    source_text = source.decode("utf-8")
    namespace: dict[str, object] = {
        "__name__": "guardrails_rules_user",
        "__file__": path,
    }
    code = compile(source_text, path, "exec")
    exec(code, namespace)
    if "RULES" not in namespace:
        raise AttributeError(f"{path!r} does not expose a RULES attribute")
    return _validate(namespace["RULES"])  # type: ignore[arg-type]


def _load_from_module(dotted: str) -> list[Rule]:
    module = importlib.import_module(dotted)
    if not hasattr(module, "RULES"):
        raise AttributeError(f"{dotted!r} does not expose a RULES attribute")
    return _validate(module.RULES)


def load_rules(
    *,
    path: str | None = None,
    module: str | None = None,
) -> list[Rule]:
    """Load a rule pack from a file path (preferred) or dotted module.

    Resolution order: explicit ``path`` > explicit ``module`` > env
    ``INVARIANT_RULES_PATH`` > env ``INVARIANT_RULES_MODULE`` > the default
    pack.
    """
    path = path or os.environ.get("INVARIANT_RULES_PATH")
    module = module or os.environ.get("INVARIANT_RULES_MODULE")
    if path:
        return _load_from_path(path)
    if module:
        return _load_from_module(module)
    return _load_from_module("guardrails.rules.default")


class RulePack:
    """Hot-reloadable handle around a rule pack.

    Holds the current rule list behind a ``RLock`` so that a concurrent
    ``reload()`` (triggered by SIGHUP / inotify) cannot tear a rule list out
    from under an in-flight evaluation. Evaluation itself is lock-free: the
    pointer is swapped atomically and rule objects are immutable.
    """

    def __init__(self, rules: list[Rule]):
        self._lock = threading.RLock()
        self._rules: tuple[Rule, ...] = tuple(rules)
        self._version = 0

    @classmethod
    def from_env(cls) -> RulePack:
        return cls(load_rules())

    @property
    def version(self) -> int:
        with self._lock:
            return self._version

    @property
    def rules(self) -> tuple[Rule, ...]:
        # tuple is immutable; returning the reference is safe without a copy.
        return self._rules

    def reload(self) -> int:
        """Re-read the rule pack from the configured source. Returns new version.

        Re-resolves ``INVARIANT_RULES_PATH`` / ``INVARIANT_RULES_MODULE`` from
        the environment on every call so a SIGHUP-triggered reload picks up
        the latest on-disk bytes (the whole point of hot-reload).
        """
        new_rules = tuple(load_rules())
        with self._lock:
            self._rules = new_rules
            self._version += 1
            return self._version
