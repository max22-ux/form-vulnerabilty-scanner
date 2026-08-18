import json
import os
from pathlib import Path

class ReportManager:
    def __init__(self,path):
        self.path = path

    def cargar_json(self):
        data = {
        "inputs": [],
        "vulnerabilidades": [], 
        "puntuaje": 0,
        "riesgo_total": [],
        "nivel_de_riesgo": ""
        }

        if not os.path.exists(self.path):
            with open(self.path, "w") as f:
                return json.dump(data,f,indent=4)

    def agregar_resultado(self,tipo,dato):
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {
            "inputs":[],
            "vulnerabilidades": [], 
            "puntuaje": 0,
            "riesgo_total": [],
            "nivel_de_riesgo" : ""
            }
        tipo = tipo.lower()

        if tipo not in data:
            print(f"[WARN] tipo '{tipo}' no existe. Se crea automaticamente")
            data[tipo] = []

        data[tipo].append(dato)

        with open(self.path,"w") as f:
            json.dump(data, f, indent=4)

    def sumar_score(self,lugar,num):
        with open(self.path,"r") as f:
            data = json.load(f)

        data[lugar] += num

        with open(self.path, "w") as f:
            json.dump(data,f,indent=4)


def report(output):  #origen del path
    # raíz del proyecto (sube niveles según dónde esté el archivo)
    ROOT_DIR = Path(__file__).resolve().parent.parent
    # ruta a report/reporte.json
    report_path = ROOT_DIR / "report" / output
    return report_path