from core.requester import Requester
from report import json_manager
import json
import html

XSS_PLAYLOADS = ["<script>alert(1)</script>",
	"\"'><script>alert(1)</script>",
	"<img src=x onerror=alert(1)>",
	]

Campos = ["text","password","email","textarea","search"]

CAMPOS_EVITABLES=["submit","hidden","button","reset","file","image"]

ERRORES_XSS = ['XSS error',
	'XSS no detectado'
	]

def verificacion_xss():
	pass

def envio_xss(method,url,direccion):
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
				
		for playload in XSS_PLAYLOADS:
			data_test = base_data.copy()
			data_test[name] = playload

			response = req.send(method, url, data=data_test)
			if not response:
				continue

			print(f"   ->  Playload: {playload}")

			#Deteccion por errores SQL
			if response: 
				decoded = html.unescape(response.text)

				if playload in decoded:
					print(f"[!!!] XSS reflejado en {name}")
					json_manager.agregar_resultado(direccion,"vulnerabilidades",{
						"url": url,
						"method": method,
						"type": "XSS",
						"campo": name,
						"payload": playload,
						"vulnerable": True
						})
				else:
					print(f"[+] XSS seguro en {name}")
					json_manager.agregar_resultado(direccion,"vulnerabilidades",{
						"url": url,
						"method": method,
						"type": "XSS",
						"campo": name,
						"payload": playload,
						"vulnerable": False
						})

