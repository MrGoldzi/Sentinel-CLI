"""Sentinel CLI entry point — used by the `sentinel` console script after pip install.

After `pip install sentinel-security`, running `sentinel scan ...` or
`sentinel dast ...` will invoke this function.
"""

from sentinel._cli import main as _cli_main


def main() -> int:
    """Invoke the CLI main entry point. Called by the `sentinel` console script."""
    return _cli_main()
