# Turno de noche: lo que el SOC humano no ve

SOC de Tarvia: lunes a viernes de 8:00 a 20:00 (Madrid). Por la noche y en fin de semana nadie mira la consola.
Suposición **optimista** para el humano: atiende la alerta en cuanto abre el turno (sin cola).

- **3.503 de 11.061 alertas** (32%) del dataset llegan fuera de horario.
- **8 de 12 incidentes** tienen alguna alerta clave fuera de horario.
- Suma de horas de ventaja del sistema (peor alerta de cada incidente): **174 h**.
- El caso fuerte es el ransomware (#2): el reconocimiento y el volcado de credenciales empiezan el sáb 10/10 02:16 y el humano no lo ve hasta el lun 12/10 08:00: **53.7 h** de ventaja para el atacante. Si llega a cifrar y tirar la web en campaña, cada una de esas horas vale unos 120.000 € de venta (≈ 6.4 M€ si la web estuviera caída todo ese tiempo, cota máxima).

| # | Incidente | Alertas fuera de horario | Alerta que más espera | Llega | El humano la ve | Espera | Sistema |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2 | Ransomware en preparación (WS-BCN-1770) | 7/11 | Comandos de reconocimiento de dominio | sáb 10/10 02:16 | lun 12/10 08:00 | **53.7 h** | < 60 s |
| 8 | Fatiga MFA (Sergio Navarro) | 2/2 | Fatiga MFA (bombardeo de notificaciones push) | sáb 10/10 23:50 | lun 12/10 08:00 | **32.2 h** | < 60 s |
| 5 | Logisoft + túnel DNS WMS01 | 18/18 | Acceso VPN de proveedor fuera de horario o desde origen nuevo | dom 25/10 01:16 | lun 26/10 08:00 | **31.7 h** | < 60 s |
| 9 | Credential stuffing + toma de cuentas | 16/16 | Credential stuffing contra login de clientes | dom 11/10 01:19 | lun 12/10 08:00 | **30.7 h** | < 60 s |
| 11 | Abuso del asistente Vela | 3/3 | Posible prompt injection en el asistente de compra | lun 12/10 21:38 | mar 13/10 08:00 | **10.4 h** | < 60 s |
| 3 | Cadena de suministro → AWS → CRM | 3/4 | Uso de credenciales cloud desde ASN inusual | jue 15/10 02:14 | jue 15/10 08:00 | **5.8 h** | < 60 s |
| 7 | Password spraying Tor → svc_backup | 2/2 | Password spraying | mar 13/10 03:10 | mar 13/10 08:00 | **4.8 h** | < 60 s |
| 12 | Criptominería JENKINS-DEV01 | 2/2 | Conexión a IP en lista de bloqueo de TI | mar 06/10 03:18 | mar 06/10 08:00 | **4.7 h** | < 60 s |
| 1 | BEC + AiTM (Laura Ferrer) | 0/5 | Inicio de sesión exitoso desde infraestructura anónima o de hosting | mié 07/10 09:44 | mié 07/10 09:44 | **0.0 h** | < 60 s |
| 4 | Skimming TPV tienda 07 | 0/5 | Herramienta de acceso remoto no autorizada | lun 12/10 16:11 | lun 12/10 16:11 | **0.0 h** | < 60 s |
| 6 | Fuga de datos empleada saliente | 0/2 | Subida masiva a almacenamiento personal | mié 14/10 18:29 | mié 14/10 18:29 | **0.0 h** | < 60 s |
| 10 | Phishing Packaging Iberia + prompt injection | 0/13 | Correo reportado como phishing por un usuario | mar 20/10 08:18 | mar 20/10 08:18 | **0.0 h** | < 60 s |

## Cómo contarlo con honestidad

- Las horas son de espera hasta que alguien **abre** la alerta; un SOC con 4.000 alertas al día tardaría más.
- Hay una guardia N2 localizable por teléfono, pero solo si alguien la llama: sin sistema, nadie la llama.
- Los 120.000 €/hora son el coste de caída de la venta online en campaña (empresa_tarvia.md): aplica a los incidentes que la paran (ransomware, skimming, robo del CRM), no a todos.
