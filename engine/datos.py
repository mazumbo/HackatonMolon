"""Carga de datos del reto. La ruta del dataset se toma de DATASET_DIR (raíz del repo DTT-UAB-The-Hack)."""
import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

MADRID = ZoneInfo("Europe/Madrid")  # el calendario de cambios está en hora local


def dataset_dir(ruta=None):
    p = Path(ruta or os.environ.get("DATASET_DIR", "../DTT-UAB-The-Hack"))
    if not (p / "03_alertas").is_dir():
        raise FileNotFoundError(f"No encuentro el dataset en {p.resolve()} (define DATASET_DIR)")
    return p


def leer_jsonl(ruta):
    with open(ruta, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def cargar_alertas(ruta=None, fichero="alertas.jsonl"):
    return leer_jsonl(dataset_dir(ruta) / "03_alertas" / fichero)


def cargar_cambios(ruta=None):
    with open(dataset_dir(ruta) / "02_inventario" / "calendario_cambios.csv", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def cargar_waf(ruta=None):
    p = dataset_dir(ruta) / "04_logs" / "waf.jsonl"
    return leer_jsonl(p) if p.exists() else []


def instante(valor):
    """ISO 8601 de las alertas (UTC, con Z) -> datetime con zona."""
    if not valor:
        return None
    try:
        return datetime.fromisoformat(str(valor).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def hora_local_cambio(valor):
    """'2026-10-08 08:00' del calendario (hora de Madrid) -> datetime UTC."""
    return datetime.strptime(valor, "%Y-%m-%d %H:%M").replace(tzinfo=MADRID).astimezone(timezone.utc)
