"""python -m agent.run_batch --ids-file ../DTT-UAB-The-Hack/03_alertas/alertas_muestra_desarrollo.jsonl --limit 10
Escriu out/tickets/<id>.json (la UI el llegeix amb UI_TICKETS=out/tickets/)."""
import argparse
import json
from pathlib import Path

import requests

from . import config
from .triar import triar


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids-file", help="JSONL amb un camp alert_id per linia")
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--out", default="out/tickets")
    a = ap.parse_args()
    if a.ids_file:
        with open(a.ids_file, encoding="utf-8") as f:
            ids = [json.loads(l)["alert_id"] for l in f if l.strip()]
    else:
        ids = [x["alert_id"] for x in requests.get(config.SOC_API_URL + "/alerts", params={"limit": a.limit}, timeout=10).json()["items"]]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    tot_in = tot_out = 0
    for aid in ids[: a.limit]:
        t = triar(aid)
        tmp = out / f"{aid}.json.tmp"
        tmp.write_text(json.dumps(t, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(out / f"{aid}.json")
        u = t.get("usage", {})
        tot_in, tot_out = tot_in + u.get("input_tokens", 0), tot_out + u.get("output_tokens", 0)
        print(f"{aid}: {t['verdict']} / {t['severity']} / {t['triage_seconds']}s")
    print(f"tokens totals: in={tot_in} out={tot_out}")


if __name__ == "__main__":
    main()
