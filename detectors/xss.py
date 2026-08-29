import json
import html
import logging
logger = logging.getLogger(__name__)

XSS_PLAYLOADS = [
	"<script>alert(1)</script>",
	"\"'><script>alert(1)</script>",
	"<img src=x onerror=alert(1)>",
	]

CAMPOS_EVITABLES= ["submit","hidden","button","reset","file","image"]

def envio_xss(method, url, inputs, req, report_manager):

	base_data = {}

	for campo in inputs:
		tipo = (campo.get("type") or "").lower()
		name = campo.get("name")
	
		if name and tipo not in CAMPOS_EVITABLES:
			base_data[name] = "test"
	
	for campo in inputs:
		tipo = (campo.get("type") or "").lower()
		name = campo.get("name")

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

			#Prueba 1
			texto_original = response.text
			texto_decodificado = html.unescape(response.text)
			reflejado = (playload in texto_original or playload in texto_decodificado) 

			if not reflejado:
				continue

			contexto = obtener_contexto(texto_decodificado,playload)

			logger.warning(
				"Payload reflejado en campo %s",
				name
				)
			if contexto:
				logger.warning(
					"Payload reflejado en %s. contexto: %s",
					name,
					contexto
					)

			report_manager.agregar_resultado("vulnerabilidades", {
			 "url": url,
			 "method": method,
			 "type": "XSS",
			 "campo": name,
			 "payload": playload,
			 "vulnerable": False,
			 "estado": "REFLEJADO",
			 "description": "El payload fue reflejado en la respuesta. Requiere análisis del contexto."
			 })
		

def obtener_contexto(texto,playload,margen=100):
	posicion = texto.find(payload)

	if posicion == -1:
		return None

	inicio = max(0, posicion - margen)
	fin = min(len(texto), posicion + len(payload) + margen)

	return texto[inicio:fin]