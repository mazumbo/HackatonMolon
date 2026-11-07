import json
from urllib.request import urlopen
from urllib.error import URLError

# Dirección de la API que ya tienes funcionando.
URL = "http://127.0.0.1:8000/alerts?limit=5"

try:
    # Pedimos cinco alertas a la API.
    with urlopen(URL, timeout=30) as respuesta:
        datos = json.load(respuesta)

    alertas = datos["items"]

    print(f"Alertas recibidas: {len(alertas)}")

    if alertas:
        print("\nContenido de la primera alerta:\n")
        print(json.dumps(alertas[0], indent=2, ensure_ascii=False))
    else:
        print("La consulta no ha devuelto alertas.")

except URLError as error:
    print("No se ha podido consultar la API.")
    print("Comprueba que la terminal del servidor sigue abierta.")
    print(f"Detalle: {error}")
