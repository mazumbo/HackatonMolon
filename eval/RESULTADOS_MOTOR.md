# Evaluación del motor (sin LLM)

Motor construido en 3.0 s: 11061 alertas, 4339 cerradas por el prefiltro, 6604 grupos.

| # | Incidente | Cerradas por prefiltro | Grupos | Alertas en el grupo principal | Severidad motor (esperada) |
| --- | --- | --- | --- | --- | --- |
| 1 | BEC + AiTM (Laura Ferrer) | 0 | 1 | 5/5 | ✅ critical (critical) |
| 2 | Ransomware en preparación (WS-BCN-1770) | 0 | 1 | 11/11 | ✅ critical (critical) |
| 3 | Cadena de suministro → AWS → CRM | 0 | 2 | 3/4 | ✅ critical (critical) |
| 4 | Skimming TPV tienda 07 | 0 | 3 | 3/5 | ✅ critical (critical) |
| 5 | Logisoft + túnel DNS WMS01 | 0 | 1 | 18/18 | ✅ high (high) |
| 6 | Fuga de datos empleada saliente | 0 | 1 | 2/2 | ✅ critical (critical) |
| 7 | Password spraying Tor → svc_backup | 0 | 1 | 2/2 | ✅ critical (critical) |
| 8 | Fatiga MFA (Sergio Navarro) | 0 | 1 | 2/2 | ✅ critical (critical) |
| 9 | Credential stuffing + toma de cuentas | 0 | 1 | 16/16 | ✅ critical (critical) |
| 10 | Phishing Packaging Iberia + prompt injection | 0 | 1 | 13/13 | ❌ high (critical) |
| 11 | Abuso del asistente Vela | 0 | 2 | 2/3 | ✅ high (high) |
| 12 | Criptominería JENKINS-DEV01 | 0 | 1 | 2/2 | ✅ critical (critical) |

**Severidad del motor igual a la política: 11/12. Incidentes con alguna alerta cerrada por el prefiltro: 0.**

El motor solo ve las alertas: el +1 por acceso confirmado que sale de los logs (p. ej. el login AiTM del incidente 10) lo añade el agente, que sí los consulta.

- Benigno de control Nóminas a la gestoría (FLUJO-0007): ALR-20261007-011874 → cerrar (benign_true_positive), ALR-20261014-011875 → cerrar (benign_true_positive)
