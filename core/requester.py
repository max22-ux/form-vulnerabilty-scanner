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
			return self.session.request(method.upper(),url, timeout=5,data=data)
		except requests.RequestException as e:
			logger.error("%s",e)
			return None


def devolver_res(url):
	#especificamos la url
	r = requests.get(url, timeout=5)
	return r

def devolver_url(url):
	return url

def nivel_de_riesgo(path,report_manager):
	with open(path, "r") as f:
		data = json.load(f)

	puntuaje = data["puntuaje"]
	if puntuaje >= 20:
		data["nivel_de_riesgo"] = "HIGH" 
	elif puntuaje >= 10:
		data["nivel_de_riesgo"] = "MEDIUM"
	else:
		data["nivel_de_riesgo"] = "LOW"

	with open(path,"w") as f:
		json.dump(data,f,indent=4)
		