from core import parser
import argparse


def obtener_argumentos():
	parse = argparse.ArgumentParser(description="Escaner de formularios vulnerables")
	parse.add_argument("-u","--url",required=True,help="URL objetivo")
	return parse.parse_args()

def main():
	print("Ejecutando escaneo de formularios web..")

	args = obtener_argumentos()
	url = args.url


	print(f"Escaneando {url}")


	parser.escaner(url)


	
if __name__ == "__main__":
	main()