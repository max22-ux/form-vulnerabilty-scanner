import requests
import json
import logging
logger = logging.getLogger(__name__)

class Requester:
	def __init__(self):
		import requests
		self.session = requests.Session()

	def send(self, method, url, data=None):
		try:
			
			if method.upper() == "GET":
				return self.session.request(method, url, params=data, timeout=5)

			return self.session.request(method, url, data=data, timeout=5)
		except requests.RequestException as e:
			logger.error("%s",e)
			return None

def devolver_res(url):
	#especificamos la url
	try:
		r = requests.get(url, timeout=5)
		return r
	except Exception as e:
		logger.error(f"Ha ocurrido un error {e}")


def nivel_de_riesgo(path,report_manager):
	with open(path, "r") as f:
		data = json.load(f)

	puntuaje = data["puntuaje"]
	if puntuaje >= 20:
		report_manager.agregar_resultado("nivel_de_riesgo","HIGH") 
	elif puntuaje >= 10:
		report_manager.agregar_resultado("nivel_de_riesgo","MEDIUM")
	else:
		report_manager.agregar_resultado("nivel_de_riesgo","LOW")
		