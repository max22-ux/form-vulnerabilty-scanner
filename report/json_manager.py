import json
import os
from pathlib import Path


def cargar_json(path):
    data = {
    "inputs": [],
    "vulnerabilidades": [], 
    "puntuaje": 0,
    "riesgo_total": []
    }

    if not os.path.exists(path):
        with open(path, "w") as f:
            return json.dump(data,f,indent=4)

def agregar_resultado(path,tipo,dato):
    #1.crear el archivo si no existe
    if not os.path.exists(path):
        cargar_json(path)

    #2.cargar json de forma segura
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        data = {
        "inputs":[],
        "vulnerabilidades": [], 
        "puntuaje": 0,
        "riesgo_total": []}
    tipo = tipo.lower()

    # 3. Validar tipo
    if tipo not in data:
        print(f"[WARN] tipo '{tipo}' no existe. Se crea automaticamente")
        data[tipo] = []

    # 4. agregar datos
    data[tipo].append(dato)

    #5. guardar
    with open(path,"w") as f:
        json.dump(data, f, indent=4)


def sumar_score(path,lugar,num):
    with open(path,"r") as f:
        data = json.load(f)

    data[lugar] += num

    with open(path, "w") as f:
        json.dump(data,f,indent=4)


def report():
    # raíz del proyecto (sube niveles según dónde esté el archivo)
    ROOT_DIR = Path(__file__).resolve().parent.parent
    # ruta a report/reporte.json
    report_path = ROOT_DIR / "report" / "reporte.json"
    return report_path