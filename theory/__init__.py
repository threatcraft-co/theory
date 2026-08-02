"""
THEORY — Multi-source Threat Actor Intelligence Framework
=========================================================

An open-source alternative to enterprise threat intelligence platforms.
Built for analysts, hunters, students, and researchers who believe
good intelligence shouldn't require a six-figure subscription.

Quick start::

    from theory import run

    profile = run(
        actor   = "APT28",
        sources = ["mitre", "malpedia", "otx"],
        output  = "dossier",
        save    = False,
    )

CLI::

    theory --actor APT28
    theory --actor "Lazarus Group" --sources mitre,malpedia,otx,sigma,threatfox
    theory --list-actors
    theory --update-bundles

GitHub: https://github.com/threatcraft-co/theory
"""

from theory._version import (
    __version__,
    __author__,
    __email__,
    __url__,
    __license__,
)

from theory._cli import main, run

__all__ = [
    "main",
    "run",
    "__version__",
    "__author__",
    "__email__",
    "__url__",
    "__license__",
]
