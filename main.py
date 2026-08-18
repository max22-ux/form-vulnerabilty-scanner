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
	if url.startswith("http://") or url.startswith("https://"):
		logging.info("Target: %s", url)
		parser.escaner(url,path)
	else:
		logging.error("No se especifico si la url, empieza con http o https")


if __name__ == "__main__":
	main()