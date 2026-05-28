#!/usr/bin/env python3
"""Scrape the compromised-packages list from a Socket.dev supply-chain-attack blog post.

The package table on those posts is rendered client-side from
    GET /api/public/supply-chain-attacks/<attackId>/packages
The attackId is embedded in the blog page's JSON props as
    "_type":"supplyChainAttackPackages", ..., "attackId":"<id>"

Cloudflare blocks plain curl/requests, so we use curl_cffi with a TLS profile
that the WAF currently lets through (chrome110 / safari17_2_ios).

Output format is chosen by the --out extension: .csv (default), .json, or .kql
(a `datatable()` literal you can paste into Sentinel / ADX / Defender hunts).

Usage:
    pip install --user curl_cffi
    python3 socket_scraper.py                                       # → output/packages.csv
    python3 socket_scraper.py <blog-url>                            # any SCA post
    python3 socket_scraper.py --attack-id 22 --out output/packages.csv
    python3 socket_scraper.py --out output/compromised.kql          # KQL datatable
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

from curl_cffi import requests

DEFAULT_URL = (
    "https://socket.dev/blog/"
    "tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack"
)
API_TMPL = "https://socket.dev/api/public/supply-chain-attacks/{attack_id}/packages"
IMPERSONATE = "chrome110"

ATTACK_ID_RE = re.compile(
    r'"_type"\s*:\s*"supplyChainAttackPackages"[^}]*?"attackId"\s*:\s*"([^"]+)"'
)


def find_attack_id(session: requests.Session, blog_url: str) -> str:
    r = session.get(blog_url, timeout=30)
    r.raise_for_status()
    m = ATTACK_ID_RE.search(r.text)
    if not m:
        raise SystemExit(f"No supplyChainAttackPackages block found at {blog_url}")
    return m.group(1)


def fetch_packages(session: requests.Session, attack_id: str, referer: str) -> list[dict]:
    r = session.get(
        API_TMPL.format(attack_id=attack_id),
        headers={"Accept": "application/json", "Referer": referer},
        timeout=60,
    )
    r.raise_for_status()
    return r.json().get("packages", [])


def _full_name(pkg: dict) -> str:
    """npm scoped names are `@scope/name`; pypi/composer use plain name."""
    ns = pkg.get("namespace") or ""
    name = pkg.get("name") or ""
    if not ns:
        return name
    if pkg.get("type") == "npm":
        return f"{ns}/{name}"
    return f"{ns}/{name}"  # composer style is `vendor/name` already in namespace


def _kql_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _kql_datetime(ts: str | None) -> str:
    return f"datetime({ts})" if ts else "datetime(null)"


def write_kql(packages: list[dict], path: Path, attack_id: str, source_url: str) -> None:
    from datetime import datetime, timezone

    header = (
        f"// Compromised packages scraped from Socket.dev\n"
        f"// Source post : {source_url}\n"
        f"// API         : https://socket.dev/api/public/supply-chain-attacks/{attack_id}/packages\n"
        f"// Generated   : {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        f"// Count       : {len(packages)}\n"
        f"//\n"
        f"// Example hunts:\n"
        f"//   CompromisedPackages | where ecosystem == 'npm' | project package, version\n"
        f"//   <YourInstallLog> | where pkg_name in ((CompromisedPackages | project package))\n"
        f"//   <YourInstallLog> | join kind=inner CompromisedPackages on $left.pkg_name == $right.package, $left.pkg_version == $right.version\n"
    )
    rows = []
    for p in packages:
        rows.append(
            "    "
            + ", ".join(
                [
                    _kql_str(p.get("type") or ""),
                    _kql_str(_full_name(p)),
                    _kql_str(p.get("version") or ""),
                    _kql_datetime(p.get("detected_at")),
                    _kql_datetime(p.get("published_at")),
                ]
            )
            + ","
        )
    if rows:
        rows[-1] = rows[-1].rstrip(",")

    body = (
        "let CompromisedPackages = datatable(\n"
        "    ecosystem: string,\n"
        "    package:   string,\n"
        "    version:   string,\n"
        "    detected_at:  datetime,\n"
        "    published_at: datetime\n"
        ")\n"
        "[\n"
        + "\n".join(rows)
        + "\n];\n"
    )
    path.write_text(header + "\n" + body, encoding="utf-8")


def write_csv(packages: list[dict], path: Path, scraped_at: str) -> None:
    """CSV shape matches the KQL datatable so externaldata() can point at it directly."""
    cols = ["ecosystem", "package", "version", "detected_at", "published_at", "scraped_at"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for p in packages:
            w.writerow([
                p.get("type") or "",
                _full_name(p),
                p.get("version") or "",
                p.get("detected_at") or "",
                p.get("published_at") or "",
                scraped_at,
            ])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("url", nargs="?", default=DEFAULT_URL, help="Socket.dev blog post URL")
    ap.add_argument("--attack-id", help="Skip page scrape and use this attack id directly")
    ap.add_argument("--out", default="scrapers-output/packages.csv", help="Output file (.csv, .json, or .kql)")
    args = ap.parse_args()

    session = requests.Session(impersonate=IMPERSONATE)

    attack_id = args.attack_id or find_attack_id(session, args.url)
    print(f"attack_id={attack_id}", file=sys.stderr)

    packages = fetch_packages(session, attack_id, referer=args.url)
    print(f"fetched {len(packages)} packages", file=sys.stderr)

    from datetime import datetime, timezone
    scraped_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    ext = out.suffix.lower()
    if ext == ".csv":
        write_csv(packages, out, scraped_at=scraped_at)
    elif ext == ".kql":
        write_kql(packages, out, attack_id=attack_id, source_url=args.url)
    else:
        out.write_text(
            json.dumps({"scraped_at": scraped_at, "attack_id": attack_id, "packages": packages}, indent=2),
            encoding="utf-8",
        )
    print(f"wrote {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
