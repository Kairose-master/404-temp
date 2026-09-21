#!/usr/bin/env python3
"""Install exact solc releases with bounded retries for reproducible images."""
from __future__ import annotations

import sys
import time


def install_versions(versions, installer, *, attempts=4, sleep=time.sleep):
    """Install each distinct version, retrying interrupted binary downloads."""
    for version in dict.fromkeys(versions):
        for attempt in range(1, attempts + 1):
            try:
                installer(version)
                print(f"installed solc {version}", flush=True)
                break
            except Exception as error:
                if attempt == attempts:
                    raise RuntimeError(
                        f"failed to install solc {version} after {attempts} attempts"
                    ) from error
                delay = min(2 ** (attempt - 1), 8)
                print(
                    f"solc {version} download failed ({error}); "
                    f"retrying in {delay}s [{attempt}/{attempts}]",
                    file=sys.stderr,
                    flush=True,
                )
                sleep(delay)


def main(argv=None):
    versions = list(argv if argv is not None else sys.argv[1:])
    if not versions:
        return 0
    import solcx
    install_versions(versions, solcx.install_solc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
