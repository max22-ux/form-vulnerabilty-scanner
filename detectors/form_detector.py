import requests
from bs4 import BeautifulSoup
from urllib.parse import *
import os
import logging
logger = logging.getLogger(__name__)

vuln_CSRF = [
	'csrf',
	'csrf_token',
	'xsrf',
	'token',
	'_token',
	'nonce',
	'user_token',
	'authenticity_token'
]

def tipo_form(tags_input,form):
	textarea = form.find('textarea')	
	if 'text' in tags_input and 'password' in tags_input and 'email' in tags_input:
		return 'Registro'
	elif ('text' in tags_input or 'email' in tags_input) and 'password' in tags_input:
		return 'Login'
	elif textarea is not None and 'submit' in tags_input:
		return 'Comentario'
	elif 'text' in tags_input and 'password' not in tags_input:
		return 'Busqueda'
	else:
		return 'No se encontro el tipo de formulario..'

#detectamos los campos basicos del formulario
def vulnerabilidades(form,res,url,path,report_manager):
	action = form.get("action")
	method = form.get("method","GET")
	logger.info("[+]Method--> %s",method) 
	if action is not None:
		logger.info("[+]Datos enviados de-[ %s://%s]-a-[%s]",res.scheme,res.hostname,action)
		logger.info("[+]action--> %s",action)
		action_url = urljoin(url,action)
	else:
		report_manager.sumar_score("puntuaje",8)
		action_url = url
		report_manager.agregar_resultado("vulnerabilidades",{'tipo':'campo action vacio',
			'detalle': 'los datos del formulario no se envian a ningun lado'})
	return action_url

#detectamos los campos vulnerables
def campos_vulnerables(tags_input,cant_input,res,form,report_manager):
	#detectamos el tipo de vulnerabilidad
	if res.scheme == 'http' and 'password' in tags_input:
		report_manager.sumar_score("puntuaje",8)
		report_manager.agregar_resultado("riesgo_total",{
			'tipo': 'Password con HTTP',
			'detalle':'La contraseña con la extencion HTTP puede ser interceptada'
			})
	method = method_form(form)
	if method == 'GET' and 'password' in tags_input:
		report_manager.sumar_score("puntuaje",8)
		report_manager.agregar_resultado("riesgo_total",{
			'tipo': 'password enviada con el metodo GET',
			'detalle':'se envia la contraseña con GET, puede ser legible'
			})
	csrf_detectado = False
	for campo in cant_input:
		campo_name = (campo.get('name') or '').lower()
		if campo_name in vuln_CSRF:
			csrf_detectado = True
			break	
		if campo.get('type') == 'hidden':
			report_manager.sumar_score("puntuaje",3)
			campo_hidden = {
			'Vulnerabilidad': 'Campo sospechoso',
			'tipo': campo.get('type'),
			'nombre':campo_name,
			'valor': campo.get('value')	
			}
			report_manager.agregar_resultado("riesgo_total",{
				'tipo': campo_hidden,
				'detalle': 'campo hidden detectado ,puede contener datos sospechosos (REVISAR)'
				})
	if not csrf_detectado:
		report_manager.sumar_score("puntuaje",4)
		report_manager.agregar_resultado("riesgo_total",{
			'tipo': 'Vulnerabilidad CSRF',
			'detalle':'Posible ausencia de protección CSRF (REVISAR)'
			}) 


def method_form(form):
	method = form.get('method','GET').upper()
	if method in ('GET','POST'):
		return method
	else:
		return None