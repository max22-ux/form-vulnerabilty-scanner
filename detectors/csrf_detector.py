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
	'authenticity_token',
	'forgery',
	'authenticity'
]

def detectar_csrf(method,cant_input,report_manager):
	csrf_detectado = False
	for campo in cant_input:
		campo_name = (campo.get('name') or '').lower()

		csrf_detectado = any(
			palabra in campo_name 
			for palabra in vuln_CSRF
			)
		
	puntuaje = 0
	if method.lower() == "post" and not csrf_detectado:
		report_manager.sumar_score("puntuaje", 2)
		puntuaje += 2 
	if method.lower() in ('put','delete') and not csrf_detectado:
		report_manager.sumar_score("puntuaje", 3)
		puntuaje += 3
	
	if puntuaje >= 2:
		logger.warning("Posible ausencia de proteccion CSRF")

		report_manager.agregar_resultado("riesgo_total",{
			"tipo": "CSRF",
			"estado": "REVISAR",
			"puntuaje": puntuaje,
			"token_detectado": False,
			"evidencias": [
				f"Formulario {method.upper()} detectado",
				"No se encontró token CSRF",
			],
			"detalle": "La ausencia de un token CSRF es un indicador de riesgo. Se requiere verificar la validación del lado del servidor"
			})
	if csrf_detectado:
		logger.info("Posible token CSRF encontrado en el formulario")