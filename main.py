from core import parser
from report import json_manager
import argparse
import logging

def obtener_argumentos():
	parse = argparse.ArgumentParser(description="Escaner de formularios vulnerables")
	parse.add_argument("-u","--url",required=True,help="URL objetivo ej:(https://google.com)")
	parse.add_argument("-o","--output",default="reporte.json",help="Nombre del json ej:(reporte.json)")
	return parse.parse_args()

def main():
	print("[Scanner iniciado]")
	args = obtener_argumentos()
	url = args.url
	output = args.output

	logging.basicConfig(
		level=logging.INFO,
		format="%(asctime)s %(levelname)s %(message)s"
		)
	
	if not output.endswith(".json"):
		output+=".json"

	path = json_manager.report(output)
	if not url.startswith("http://") and not url.startswith("https://"):
		logging.error("la Url debe iniciar con http o https")
	else:
		logging.info("Target: %s", url)
		parser.escaner(url,path)


if __name__ == "__main__":
	main()