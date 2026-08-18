from core.requester import Requester
import json
import html
import logging
logger = logging.getLogger(__name__)

XSS_PLAYLOADS = [
	"<script>alert(1)</script>",
	"\"'><script>alert(1)</script>",
	"<img src=x onerror=alert(1)>",
	]
CAMPOS_EVITABLES=["submit","hidden","button","reset","file","image"]


def envio_xss(method,url,path,report_manager):
	with open(path,"r") as f:
		datos = json.load(f)
	base_data = {}
	for dato in datos["inputs"]:
		tipo = dato.get("tipo")
		name = dato.get("name")
		if name and tipo not in CAMPOS_EVITABLES:
			base_data[name] = "test"
	#fuzzing
	req = Requester()
	for dato in datos["inputs"]:
		tipo = dato.get("tipo")
		name = dato.get("name")

		if not name or tipo in CAMPOS_EVITABLES:
			continue

		logger.info("Probando campos: %s",name)
		for playload in XSS_PLAYLOADS:
			data_test = base_data.copy()
			data_test[name] = playload

			response = req.send(method, url, data=data_test)
			logger.info("->Playload: %s",playload)
			if not response:
				continue
			
			decoded = html.unescape(response.text)
			if playload in decoded:
				logger.warning("Posible XSS reflejado") #aparece root, se puede cambiar
				report_manager.agregar_resultado("vulnerabilidades",{
					"url": url,
					"method": method,
					"type": "XSS",
					"campo": name,
					"playload": playload,
					"vulnerable": True
					})



"""
Pero hay una limitación importante
Actualmente tu detector realmente está detectando:
"El payload aparece reflejado en la respuesta"

No necesariamente:
"Existe XSS ejecutable"
Son cosas diferentes.

Tienes:
if not response:
    continue
y posteriormente:

if response:
El segundo if ya es innecesario, porque si response fuera falso ya hiciste continue.

Es decir, conceptualmente:
response no existe
       ↓
    continue
       ↓
response existe
       ↓
analizar respuesta

Por lo tanto ese segundo if response: sobra.
Y hay algo muy interesante que podrías agregar
Ahora mismo tienes:
payload
   ↓
respuesta
   ↓
¿payload aparece?
   ↓
Posible XSS

Podrías evolucionarlo a:

payload
   ↓
respuesta
   ↓
¿payload aparece?
   │
   ├── NO → no detectado
   │
   └── SÍ
        ↓
   ¿está HTML-encoded?
        │
        ├── SÍ → reflexión, pero posiblemente escapada
        │
        └── NO
             ↓
       reflexión potencialmente peligrosa
Eso sería una mejora bastante interesante para tu proyecto porque ya no solamente estarías preguntando "¿apareció mi payload?", sino también "¿cómo apareció?".
Mi valoración

Para un mini scanner educativo, yo diría que tu detector está bastante bien estructurado:
Parte	Valoración
Lectura de inputs	✅
Exclusión de campos	✅
Fuzzing campo por campo	✅
Varios payloads	✅
Copia de parámetros	✅
html.unescape()	✅ Buena idea
Detección de reflexión	✅
Reporte JSON	✅
Confirmación de ejecución XSS	⚠️ Falta
Diferenciación de contexto HTML/atributo/JS	⚠️ Falta

Lo más importante: no intentaría hacer que este detector diga simplemente XSS = True cuando encuentra el payload. 
Mantendría vulnerable: True solo cuando tengas suficientes evidencias, o incluso podrías distinguir entre "reflejado", "potencial" y "confirmado". 
Eso haría que tu scanner se vea mucho más serio.


"""