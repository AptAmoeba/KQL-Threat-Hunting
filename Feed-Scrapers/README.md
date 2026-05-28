# socket-scraper

One scraper (for now) that publishes compromised-package threat intel as KQL-friendly CSVs
in [`output/`](output/). Point a Sentinel / ADX / Defender XDR query at the
raw GitHub URLs and you're hunting.

| CSV | Source | Refresh |
|---|---|---|
| `output/packages.csv`           | Socket.dev — Mini Shai-Hulud (attack 22) | Daily |

## Using it in KQL

Paste at the top of any query window — no table import needed.

### Socket feed

```kql
let SocketPackages = externaldata(
    ecosystem:string, package:string, version:string,
    detected_at:datetime, published_at:datetime, scraped_at:datetime
)
[@"https://raw.githubusercontent.com/<owner>/<repo>/main/output/packages.csv"]
with (format="csv", ignoreFirstRecord=true);

SocketPackages | summarize count() by ecosystem
```

### Feed freshness

```kql
SocketPackages
| summarize last_refresh = max(scraped_at)
| extend stale = last_refresh < ago(2d)
```

## Gotchas
- **Socket workflow dormancy**: self-disables when attack 22 has been quiet
  for ≥ 30 days. Re-enable from *Actions → Refresh Socket.dev → Enable workflow*.
- **Private repos**: `externaldata()` needs an anonymous-readable URL — either
  make the repo public, or use a Sentinel Watchlist instead.