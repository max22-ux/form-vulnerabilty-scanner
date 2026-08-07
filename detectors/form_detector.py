import requests
from bs4 import BeautifulSoup
from urllib.parse import *
from report import json_manager
import os

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

def vulnerabilidades(form,res,url,path):
	action = form.get("action")
	method = form.get("method","GET")
	print(f"[+]Method--> {method}")
	enctype = form.get("enctype")
	if action is not None:
		print(f"[+]Datos enviados de-[{res.scheme}://{res.hostname}]-a-[{action}]")
		print(f"[+]action--> {action}")
		action_url = urljoin(url,action)
	else:
		json_manager.sumar_score(path,"puntuaje",8)
		action_url = url
		json_manager.agregar_resultado(path,"vulnerabilidades",{'tipo':'campo action vacio',
			'detalle': 'los datos del formulario no se envian a ningun lado'})
	if enctype is not None:
		print(f"[+]Enctype--> {enctype}")
	else:
		json_manager.sumar_score(path,"puntuaje",8)
		json_manager.agregar_resultado(path,"vulnerabilidades",{
			'tipo': 'Enctype no especificado',
			'detalle': 'metodo del formulario no encontrado'
			})
	return action_url


def campos_vulnerables(tags_input,cant_input,res,form):
	#detectamos el tipo de vulnerabilidad
	path = json_manager.report()
	if res.scheme == 'http' and 'password' in tags_input:
		json_manager.sumar_score(path,"puntuaje",8)
		json_manager.agregar_resultado(path,"riesgo_total",{
			'tipo': 'Password con HTTP',
			'detalle':'La contraseña con la extencion HTTP puede ser interceptada'
			})
	method = method_form(form)
	if method == 'GET' and 'password' in tags_input:
		json_manager.sumar_score(path,"puntuaje",8)
		json_manager.agregar_resultado(path,"riesgo_total",{
			'tipo': 'password enviada con el metodo GET',
			'detalle':'se envia la contraseña con GET, puede ser legible'
			})
	csrf_detectado = False
	for campo in cant_input:
		campo_name = (campo.get('name') or '').lower()
		if not any(token in campo_name for token in vuln_CSRF):  #any() devuelve True o False
			csrf_detectado = True
			break

	if csrf_detectado:
		json_manager.sumar_score(path,"puntuaje",8)
		json_manager.agregar_resultado(path,"riesgo_total",{
			'tipo': 'Vulnerabilidad CSRF',
			'detalle':'No se detecto token CSRF valido'
			}) 

		if campo.get('type') == 'hidden':
			json_manager.agregar_resultado(path,"score",3)
			campo_hidden = {
			'Vulnerabilidad': 'Campo sospechoso',
			'tipo': campo.get('type'),
			'nombre':campo_name,
			'valor': campo.get('value')	
			}
			json_manager.agregar_resultado(path,"riesgo_total",{
				'tipo': campo_hidden,
				'detalle': 'campo sospechoso'
				})		
	return path


def method_form(form):
	method = form.get('method','GET').upper()
	return method