"""
Arquivo WSGI para implantação no Render.
Este arquivo serve como ponto de entrada para o Gunicorn.
"""

import sys
import os

# Adicionar o diretório raiz ao path para importar módulos
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Importar a aplicação Flask
from src.main import app

# Objeto app que será usado pelo Gunicorn
if __name__ == "__main__":
    app.run()
