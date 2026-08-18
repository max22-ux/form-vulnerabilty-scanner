from bs4 import BeautifulSoup
from urllib.parse import *
from core import requester
from detectors import form_detector, sqli, xss
from report.json_manager import ReportManager 
import logging
logger = logging.getLogger(__name__)

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

def escaner(url,path):
	try:
		res = requester.devolver_res(url)
		url = requester.devolver_url(url)
		soup = BeautifulSoup(res.text,"html.parser")
		cont = 0
		cont=len(soup.find_all('form'))
		logger.info("Forms detectados %d", cont)
		logger.info("contenido: %s",res.headers['Content-Type'])
		logger.info("%s %d %s --> %s", res.request.method, res.status_code, status_massaje.get(res.status_code), soup.title)
		form(soup,url,res,path)
	except Exception as e:
		logger.error("Ha ocurrido un error %s",e)

def form(soup,url,r,path):
	report_manager = ReportManager(path)
	report_manager.cargar_json()
	for form in soup.find_all('form'):
		res = urlparse(url)		
		action_url = form_detector.vulnerabilidades(form,res,url,path,report_manager)
		if urlparse(action_url).netloc != urlparse(url).netloc:
			logger.warning("Saltando dominio externo")
			continue
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
		logger.info("Formulario detectado: posible %s",tipo_formulario)
	
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
				report_manager.agregar_resultado("inputs",datos)
				logger.info(f"%s %d--> Found %s --> Nombre:%s --> Valor:%s",r.request.method,r.status_code,type_tag.get('type'),cant_input[cant].get('name') ,cant_input[cant].get('value'))
			else:
				logger.error("Not found --> Campo: %s",type_tag)
		print("\n")
		#detectar el tipo de vulnerabilidad en cada campo
		form_detector.campos_vulnerables(tags_input,cant_input,res,form,report_manager)
		method = form_detector.method_form(form)

		#Probamos los playloads	
		sqli.envio_sql(method,action_url,path,report_manager)
		xss.envio_xss(method,action_url,path,report_manager)
		requester.nivel_de_riesgo(path,report_manager)