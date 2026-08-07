import requests
class Requester:
	def __init__(self):
		import requests
		self.session = requests.Session()

	def send(self, method, url, data=None):
		try:
			return self.session.request(method.upper(),url, timeout=5,data=data)
		except requests.RequestException as e:
			print(f"[ERROR] {e}")
			return None


def devolver_res(url):
	#especificamos la url
	r = requests.get(url)
	return r

def devolver_url(url):
	return url


