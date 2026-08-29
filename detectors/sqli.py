import requests
import logging
logger = logging.getLogger(__name__)

SQL_PAYLOADS = [
	"' OR '1'='1",
	"' OR 1=1 --"
]

CAMPOS_EVITABLES=["submit","hidden","button","reset","file","image"]

ERRORES_SQL = [
	"you have an error in your sql syntax",
    "mysql_fetch",
    "mysqli_",
    "pdoexception",
    "sqlstate",
    "odbc sql server driver",
    "ora-",
    "postgresql",
    "sqlite error",]

def envio_sql(method, url, inputs, req, report_manager):

	base_data = {}
	
	for campo in inputs:
		tipo = (campo.get("type") or "").lower()
		name = campo.get("name")

		#saltamos campos, que no nos sirven 
		if name and tipo not in CAMPOS_EVITABLES:
			base_data[name] = "test"

	#fuzzing

	for campo in inputs:

		tipo = (campo.get("type") or "").lower()
		name = campo.get("name")

		if not name or tipo in CAMPOS_EVITABLES:
			continue

		logger.info("Probando campos: %s",name)

		base_response = req.send(
			method,
			url,
			data=base_data
			)

		if base_response is None:
			return				
		
		for payload in SQL_PAYLOADS:
			data_test = base_data.copy()
			data_test[name] = payload

			response = req.send(
				method, 
				url, 
				data=data_test
				)

			if response is None:
				continue

			logger.info("-> Playload: %s",payload)
	
			vulnerabilidad = False
			
			pruebas = comprobar_vulnerabilidad(
				base_response,response
				)

			if pruebas["puntuaje"] >= 5:
				vulnerabilidad = True
				logger.warning("Posible SQLI")
				report_manager.agregar_resultado("vulnerabilidades",{
					"url": url,
					"method": method,
					"type": "SQLi",
					"campo": name,
					"sql_error": payload,
					"vulnerable": True,
					"evidencias":pruebas["evidencia"]
					})
			elif pruebas["puntuaje"] >= 4:
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

	misma_respuesta = base_response.text == response.text

	diferencia = abs(longitud - base_longitud)
	cambio_significativo = ( diferencia > max(100, base_longitud * 0.05))

	#Deteccion por errores SQL
	vulnerable = False
	for error in ERRORES_SQL:
		if response and error.lower() in response.text.lower():
			vulnerable = True
			evidencias["evidencia"].append({"Playload":error})
			break

	if vulnerable:
		evidencias["puntuaje"] += 3

	if base_response.status_code != response.status_code:
		evidencias["puntuaje"] += 1
		evidencias["evidencia"].append({"status_changed":True})

	if cambio_significativo:
		evidencias["puntuaje"] += 1
		evidencias["evidencia"].append({"length_changed":True})

	if not misma_respuesta:
		evidencias["puntuaje"] += 1
		evidencias["evidencia"].append({"response_different":True})

	return evidencias