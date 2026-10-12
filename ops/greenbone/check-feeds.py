from __future__ import annotations

import json
import re
import time
from pathlib import Path
from xml.etree import ElementTree as ET

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp

EXPECTED_FEEDS = {"NVT", "SCAP", "CERT", "GVMD_DATA"}
PASSWORD_PATH = Path("/run/secrets/greenbone_admin_password")
SOCKET_PATH = "/run/gvmd/gvmd.sock"


def main() -> None:
    password = PASSWORD_PATH.read_text(encoding="utf-8").strip()
    if not password:
        raise RuntimeError("Greenbone credential is empty")
    with Gmp(connection=UnixSocketConnection(path=SOCKET_PATH)) as gmp:
        gmp.authenticate("admin", password)
        root = ET.fromstring(gmp.get_feeds())
    if root.attrib.get("status") != "200":
        raise RuntimeError("Greenbone feed query failed")
    feeds = []
    seen = set()
    for feed in root.findall(".//feed"):
        feed_type = (feed.findtext("type") or "").strip()
        if feed_type not in EXPECTED_FEEDS or feed_type in seen:
            continue
        name = (feed.findtext("name") or "").strip()
        version = (feed.findtext("version") or "").strip()
        if not name or len(name) > 200 or re.fullmatch(r"\d{12}", version) is None:
            raise RuntimeError(f"Greenbone {feed_type} metadata is incomplete")
        seen.add(feed_type)
        feeds.append({"type": feed_type, "name": name, "version": version})
    if seen != EXPECTED_FEEDS:
        raise RuntimeError("Greenbone required feed metadata is incomplete")
    print(json.dumps({
        "checked_at": time.time(),
        "feeds": sorted(feeds, key=lambda item: item["type"]),
    }, separators=(",", ":")))


if __name__ == "__main__":
    main()