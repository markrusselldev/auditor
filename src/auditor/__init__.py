"""Website audit scanner."""

# Single source of truth for the version. pyproject reads this (dynamic = ["version"],
# parsed statically via setuptools' attr directive), and the CLI's --version reports it.
# Bump on each release, add a CHANGELOG entry, and tag vX.Y.Z. Semantic Versioning.
__version__ = "0.10.0"
