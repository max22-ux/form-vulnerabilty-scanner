from bs4 import BeautifulSoup
from urllib.parse import *
from core import requester
from detectors import form_detector, sqli, xss
from report import json_manager


status_massaje = {
	200: 'OK',
	201: 'Created',
	204: 'No Content',
	301: 'Redirect',
	302: 'Redirect',
	400: 'Bad request',
	401: 'Unauthorized',
	404: 'Not Found',
	500: 'Server Error'
}

def escaner(url):
	try:
		res = requester.devolver_res(url)
		url = requester.devolver_url(url)
		soup = BeautifulSoup(res.text,"html.parser")
		print(f"[+]Campo field detectado {soup.find_all('fieldset')}")
		print(f"[+]contenido: {res.headers['Content-Type']}")
		print(f"[+]{res.request.method} {res.status_code} {status_massaje.get(res.status_code)} --> {soup.title}")
		form(soup,url,res)
	except Exception as e:
		print(f"Ha ocurrido un error.{e}")

def form(soup,url,r):
	for form in soup.find_all('form'):
		res = urlparse(url)
		path = json_manager.report()
		json_manager.cargar_json(path)
		action_url = form_detector.vulnerabilidades(form,res,url,path)
		tags_input = []
		cant_input = []

		#Busca los inputs dentro del formulario y el type y lo guardamos en un array		
		formulario = form.find_all('input')
		for f in formulario:
			cant_input.append(f)
			tags_input.append(f.get('type'))
		print("\n")
		#Detectar el tipo de formulario
		tipo_formulario = form_detector.tipo_form(tags_input,form)
		print(f'[+] Formulario detectado como --> {tipo_formulario}')
	
		#imprimimos los campos
		for cant in range(len(formulario)):
			type_tag = cant_input[cant]
			if type_tag is not None:
				tipo = type_tag.get('type')
				name = cant_input[cant].get('name')
				valor =cant_input[cant].get('value')
				datos = {"tipo":tipo,
					"name":name,
					"value":valor}
				json_manager.agregar_resultado(path,"inputs",datos)
				print(f"[+]{r.request.method} {r.status_code}--> Found {type_tag.get('type')} --> Nombre:{cant_input[cant].get('name')} --> Valor:{cant_input[cant].get('value')}")
			else:
				print(f"[-]Not found --> Campo:{type_tag}")
		print("\n")
		#detectar el tipo de vulnerabilidad en cada campo
		direccion = form_detector.campos_vulnerables(tags_input,cant_input,res,form)
		method = form_detector.method_form(form)

		#Probamos los playloads	
		sqli.envio_sql(method,action_url,direccion)
		xss.envio_xss(method,action_url,direccion)
