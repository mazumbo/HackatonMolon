"""Matriu de severitat de politica_soc.md. PROVISIONAL: el rol A te la versio definitiva; substituir-la."""

LEVELS = ["informational", "low", "medium", "high", "critical"]
CRIT = {"low": 0, "baja": 0, "baix": 0, "medium": 1, "media": 1, "mitjana": 1,
        "high": 2, "alta": 2, "critical": 3, "critica": 3, "crítica": 3}
MATRIX = {
    "informational": ["informational", "informational", "low", "low"],
    "low": ["informational", "low", "low", "medium"],
    "medium": ["low", "medium", "medium", "high"],
    "high": ["medium", "high", "high", "critical"],
    "critical": ["high", "critical", "critical", "critical"],
}


def compute_severity(f):
    """f = severity_factors del model. Retorna (severitat, justificacio)."""
    rule = f.get("rule_severity", "medium")
    rule = rule if rule in MATRIX else "medium"
    crit_raw = str(f.get("asset_criticality", "unknown")).lower()
    unknown = crit_raw not in CRIT
    crit = CRIT.get(crit_raw, 1)
    base = MATRIX[rule][crit]
    up = bool(f.get("confirmed_execution_or_access") or f.get("privileged_or_vip") or f.get("personal_or_payment_data"))
    down = bool(f.get("blocked_before_effect")) and not f.get("confirmed_execution_or_access")
    adj = (1 if up else 0) - (1 if down else 0)
    final = LEVELS[max(0, min(4, LEVELS.index(base) + adj))]
    why = f"Regla {rule} x activo {'desconocido (se asume media)' if unknown else crit_raw} = {base}; ajuste {adj:+d}."
    if f.get("authorized_flow"):
        final = "informational" if base == "informational" else "low"
        why += " Flujo/cambio autorizado: benign_true_positive, severidad informational/low."
    return final, why
