from __future__ import annotations

import time
from pathlib import Path


def main() -> None:
    conf_path = Path("/config/daygle_server_manager.conf")
    while True:
        if conf_path.exists():
            print("[worker] config found, worker heartbeat ok")
        else:
            print("[worker] waiting for config file at /config/daygle_server_manager.conf")
        time.sleep(60)


if __name__ == "__main__":
    main()
