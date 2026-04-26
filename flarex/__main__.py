import socket
import sys
import os
from flarex.cli.app import app


def _is_privileged() -> bool:
    if os.name == "nt":
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0


def main() -> None:
    if not _is_privileged():
        if os.name == "nt":
            msg = "flarex requires Administrator privileges to send raw packets."
        else:
            msg = "flarex requires root privileges to send raw packets."
        print(msg, file=sys.stderr)
        sys.exit(1)
    try:
        app()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
    except ValueError as e:
        print(f"flarex: {e}", file=sys.stderr)
        sys.exit(2)
    except socket.gaierror as e:
        print(f"flarex: could not resolve hostname ({e.strerror or e})", file=sys.stderr)
        sys.exit(2)
    except PermissionError as e:
        print(f"flarex: permission denied ({e})", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
