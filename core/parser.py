from bs4 import BeautifulSoup
from urllib.parse import *
from core import requester
from core.requester import Requester
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
	
	forms = soup.find_all('form')

	for numero_form, form in enumerate(forms):

		res = urlparse(url)		
		
		action_url = form_detector.vulnerabilidades(
			form, res, url, path, report_manager
			)
		
		if urlparse(action_url).netloc != urlparse(url).netloc:
			logger.warning("Saltando dominio externo")
			continue
		
		tags_input = []
		cant_input = []
	
		formulario = form.find_all('input')

		for campo in formulario:
			cant_input.append(campo)
			tags_input.append(campo.get('type'))
		print("\n")


		tipo_formulario = form_detector.tipo_form(
			tags_input,
			form
			)

		logger.info(
			"Formulario #%d - Inputs detectados: %d",
			numero_form,
			len(cant_input)
			)
		
		logger.info(
			"Formulario #%d detectado posible: %s",
			numero_form,
			tipo_formulario
			)
	
		#imprimimos los campos
		for campo in cant_input:
			tipo = campo.get('type')
			name = campo.get('name')
			valor = campo.get('value')

			datos = {
			"Formulario":numero_form,
			"tipo":tipo,
			"name":name,
			"value":valor
			}

			report_manager.agregar_resultado(
				"inputs",datos
				)
			logger.info(f"%s %d--> Found %s --> Nombre:%s --> Valor:%s",r.request.method, r.status_code, tipo, name , valor)
		print("\n")
		
		#detectar el tipo de vulnerabilidad en cada campo
		form_detector.campos_vulnerables(
			tags_input,
			cant_input,
			res,
			form,
			report_manager,
			action_url
			)
		
		method = form_detector.method_form(form)

		#Probamos los playloads	
		req = Requester()
		sqli.envio_sql(
			method, 
			action_url, 
			cant_input,
			req,
			report_manager
			)

		xss.envio_xss(
			method, 
			action_url, 
			cant_input,
			req, 
			report_manager
			)

	requester.nivel_de_riesgo(path,report_manager)