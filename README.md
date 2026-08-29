# form-vulnerability-scanner

🔎 Web Form Vulnerability Scanner

Scanner desarrollado en Python para analizar formularios HTML y detectar posibles vulnerabilidades de seguridad mediante análisis estático y pruebas controladas de entradas.

El proyecto analiza los formularios encontrados en una URL objetivo, identifica sus campos y métodos HTTP, realiza diferentes comprobaciones de seguridad y genera un reporte en formato JSON.

⚠️ Uso ético: Este proyecto fue desarrollado con fines educativos y de análisis de seguridad. Utilízalo únicamente sobre sistemas propios o sobre aquellos para los que tengas autorización explícita.


🚀 Características

🔎 Detección y análisis de formularios HTML.
📝 Identificación de inputs y sus tipos.
🌐 Análisis del método HTTP utilizado por el formulario.
🔗 Análisis de la URL action.
🔐 Detección de posibles problemas relacionados con contraseñas.
🛡️ Detección heurística de posibles problemas de protección CSRF.
💉 Pruebas de posibles SQL Injection.
📜 Pruebas de posibles XSS reflejado.
📊 Sistema de puntuación de riesgo.
📄 Generación de reportes en formato JSON.
🧩 Arquitectura modular para facilitar futuras mejoras.


🛠️ Tecnologías

Python 3
Requests — solicitudes HTTP.
BeautifulSoup — análisis del HTML.
argparse — argumentos de línea de comandos.
JSON — generación de reportes.


📁 Estructura del proyecto

web-form-vulnerability-scanner/
│
├── main.py
│
├── core/
│   ├── parser.py
│   └── requester.py
│
├── detectors/
│   ├── form_detector.py
│   ├── csrf_detector.py
│   ├── sqli.py
│   └── xss.py
│
└── report/
    └── json_manager.py


Descripción de los módulos

Módulo				Función
main.py				Punto de entrada y argumentos CLI
parser.py			Obtención y análisis de la página
requester.py			Gestión de solicitudes HTTP
form_detector.py		Análisis de formularios e inputs
csrf_detector.py		Detección heurística de posibles problemas CSRF
sqli.py				Pruebas de posibles SQL Injection
xss.py				Pruebas de posibles XSS reflejado
json_manager.py			Gestión del reporte JSON


⚙️ Instalación

Clona el repositorio:
git clone https://github.com/max-u22/TU-REPOSITORIO.git
cd TU-REPOSITORIO

Instala las dependencias:

pip install requests beautifulsoup4


💻 Uso

El scanner requiere una URL mediante -u o --url.

python main.py -u http://localhost:8080

También puedes especificar el nombre del archivo de salida:

python main.py -u http://localhost:8080 -o resultado.json


Argumentos

Argumento	Descripción
-u, --url	URL objetivo
-o, --output	Nombre del reporte JSON

Ejemplo:

python main.py --url http://localhost:8080 --output reporte.json


🔍 ¿Qué analiza?

Formularios

El scanner identifica los formularios presentes en la página y analiza individualmente sus campos.

Entre la información recopilada se encuentran:
Tipo de input.
Nombre del campo.
Valor.
Método HTTP.
URL de destino (action).
Tipo aproximado de formulario.

Los formularios son procesados de manera independiente para evitar mezclar sus campos.


SQL Injection:
El scanner utiliza payloads de prueba y compara las respuestas obtenidas con una respuesta base.

Se analizan indicadores como:
Errores relacionados con SQL.
Cambios en el código de estado HTTP.
Cambios significativos en la longitud de la respuesta.
Diferencias entre la respuesta base y la respuesta modificada.

El resultado se considera un indicador de posible SQL Injection, no una confirmación definitiva.


XSS:
Se utilizan diferentes payloads para comprobar si una entrada es reflejada en la respuesta HTTP.

Cuando se detecta una reflexión, el scanner registra:
Campo afectado.
Payload utilizado.
URL.
Método HTTP.
Estado de la detección.
Contexto aproximado de la reflexión.

Una reflexión no implica automáticamente que exista XSS explotable y requiere análisis adicional.

CSRF:
El scanner realiza una detección heurística buscando posibles tokens CSRF en los campos del formulario.

La ausencia de un token se marca como:
REVISAR

Esto no confirma por sí solo una vulnerabilidad, ya que la protección CSRF también puede implementarse mediante otros mecanismos del lado del servidor.


📊 Sistema de riesgo

El scanner utiliza un sistema de puntuación para calcular un nivel general de riesgo.

Actualmente se utilizan tres niveles:
LOW
MEDIUM
HIGH

El resultado se almacena en el reporte JSON junto con las evidencias encontradas durante el análisis.


📄 Reporte

El scanner genera un archivo JSON con información sobre:
inputs
vulnerabilidades
puntuaje
riesgo_total
nivel_de_riesgo

Ejemplo simplificado:
{
    "inputs": [],
    "vulnerabilidades": [],
    "puntuaje": 0,
    "riesgo_total": [],
    "nivel_de_riesgo": []
}


⚠️ Limitaciones

Este proyecto se encuentra en desarrollo y las detecciones son principalmente heurísticas.

Por ejemplo:
Un cambio en una respuesta HTTP no confirma una SQL Injection.
Una reflexión de un payload no confirma automáticamente XSS explotable.
La ausencia de un token encontrado por el scanner no confirma necesariamente una vulnerabilidad CSRF.
El análisis está limitado a los formularios accesibles desde la página analizada.
No sustituye herramientas profesionales de análisis de seguridad ni una auditoría manual.


🔮 Próximas mejoras

Algunas mejoras previstas:
Mejorar la detección de XSS según el contexto de reflexión.
Mejorar la detección de CSRF.
Añadir más técnicas de detección de vulnerabilidades.
Mejorar la clasificación de formularios.
Reducir falsos positivos.
Mejorar el sistema de puntuación.
Mejorar la presentación del reporte.
Añadir tests automatizados.
Incorporar crawling de múltiples páginas.


🎯 Objetivo del proyecto

El objetivo principal es desarrollar una herramienta educativa que permita practicar conceptos relacionados con:
Seguridad web.
HTTP.
Análisis de formularios HTML.
SQL Injection.
Cross-Site Scripting.
CSRF.
Automatización con Python.
Análisis de respuestas HTTP.
Desarrollo de herramientas de seguridad.


⚖️ Disclaimer

Este proyecto debe utilizarse únicamente en aplicaciones, servidores y sistemas sobre los que tengas autorización para realizar pruebas de seguridad.

El autor no se responsabiliza por el uso indebido de esta herramienta.
