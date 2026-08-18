import requests
from core.requester import Requester
import json
import logging
logger = logging.getLogger(__name__)

SQL_PLAYLOADS = [
	"' OR '1'='1",
	"' OR 1=1 --"
]

CAMPOS_EVITABLES=["submit","hidden","button","reset","file","image"]

ERRORES_SQL = [ "sql syntax",
    "mysql",
    "syntax error",
    "warning",
    "unterminated",
    "odbc",
    "pdo",
    "database error"]

def envio_sql(method,url,path,report_manager):
	with open(path,"r") as f:
		datos = json.load(f)
	
	base_data = {}
	for dato in datos["inputs"]:
		tipo = dato.get("tipo")
		name = dato.get("name")

		#saltamos campos, que no nos sirven 
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
				
		for playload in SQL_PLAYLOADS:
			data_test = base_data.copy()
			data_test[name] = playload

			base_response = req.send(method,url,data=base_data)
			response = req.send(method, url, data=data_test)

			if base_response is None:
				continue

			if not response:
				continue

			logger.info("-> Playload: %s",playload)
	
			vulnerabilidad = False
			pruebas = comprobar_vulnerabilidad(base_response,response)
			if pruebas["puntuaje"] >= 4:
				vulnerabilidad = True
				if vulnerabilidad:
					logger.warning("Posible SQLI")
					report_manager.agregar_resultado("vulnerabilidades",{
						"url": url,
						"method": method,
						"type": "SQLi",
						"campo": name,
						"playload": playload,
						"vulnerable": True,
						"evidencias":pruebas["evidencia"]
						})
			elif pruebas["puntuaje"] >= 3:
				logger.warning("Comportamiento SQLi sospechoso")

			else:
				logger.info("Comportamiento normal")


def comprobar_vulnerabilidad(base_response,response):
	evidencias = {
	"puntuaje":0,
	"evidencia":[]
	}
	base_longitud = len(base_response.text)
	longitud = len(response.text)

	misma_longitud = base_longitud == longitud 
	mismo_status = base_response.status_code == response.status_code
	misma_respuesta = base_response.text == response.text
	
	#Deteccion por errores SQL
	vulnerable = False
	for error in ERRORES_SQL:
		if response and error.lower() in response.text.lower():
			vulnerable = True
			evidencias["evidencia"].append({"Playload":error})
			break

	if vulnerable:
		evidencias["puntuaje"] += 1

	if base_response.status_code != response.status_code:
		evidencias["puntuaje"] += 1
		evidencias["evidencia"].append({"status_changed":True})

	if not misma_longitud:
		evidencias["puntuaje"] += 1
		evidencias["evidencia"].append({"length_changed":True})

	if not misma_respuesta:
		evidencias["puntuaje"] += 1
		evidencias["evidencia"].append({"response_different":True})

	return evidencias