import sys
import os
from datetime import datetime
import logging
import json
import requests
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import io
# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
# Configuração do banco de dados
from src.config import Config
from src.database import db
from src.models.usuario import Usuario
from src.models.produto import Produto
# Inicialização do app Flask
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = os.environ.get('SECRET_KEY', 'chave_secreta_padrao')
# Inicializar o banco de dados
db.init_app(app)
# Criar tabelas se não existirem
with app.app_context():
    db.create_all()
    
    # Verificar se existe um usuário admin
    admin = Usuario.query.filter_by(nome='admin').first()
    if not admin:
        # Criar usuário admin
        hashed_password = generate_password_hash('admin')
        admin = Usuario(nome='admin', senha_hash=hashed_password, admin=1)
        db.session.add(admin)
        db.session.commit()
        logger.info("Usuário admin criado com sucesso")
# Funções auxiliares
def buscar_produto_local(ean, usuario_id):
    produto = Produto.query.filter_by(ean=ean, usuario_id=usuario_id).first()
    if produto:
        return produto.to_dict()
    return None

# Restante do código...

@app.route('/api/validar-lista', methods=['POST'])
def api_validar_lista():
    if 'usuario_id' not in session or not session.get('admin'):
        return jsonify({"success": False, "message": "Não autorizado"})
    
    dados = request.json
    if not dados or 'nome_usuario' not in dados or 'data_envio' not in dados:
        return jsonify({"success": False, "message": "Dados incompletos"})
    
    # Verificar se o responsável PIN foi fornecido
    if 'responsavel_pin' not in dados:
        return jsonify({"success": False, "message": "Responsável não informado"})
    
    validador_id = session['usuario_id']
    responsavel_pin = dados['responsavel_pin']
    
    # Validar a lista com o responsável PIN
    if validar_lista_com_responsavel(dados['data_envio'], dados['nome_usuario'], validador_id, responsavel_pin):
        return jsonify({
            "success": True,
            "message": "Lista validada com sucesso"
        })
    else:
        return jsonify({
            "success": False,
            "message": "Erro ao validar lista"
        })

def validar_lista_com_responsavel(data_envio, nome_usuario, validador_id, responsavel_pin):
    """
    Valida uma lista de produtos com o responsável PIN
    """
    try:
        # Buscar o usuário que enviou a lista
        usuario = Usuario.query.filter_by(nome=nome_usuario).first()
        if not usuario:
            logger.error(f"Usuário {nome_usuario} não encontrado")
            return False
        
        # Buscar o validador
        validador = Usuario.query.get(validador_id)
        if not validador:
            logger.error(f"Validador ID {validador_id} não encontrado")
            return False
        
        # Buscar produtos da lista
        produtos = Produto.query.filter_by(
            usuario_id=usuario.id,
            data_envio=data_envio,
            enviado=1,
            validado=0
        ).all()
        
        if not produtos:
            logger.error(f"Nenhum produto encontrado para validação")
            return False
        
        # Data atual formatada
        data_atual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Validar todos os produtos da lista
        for produto in produtos:
            produto.validado = 1
            produto.validador_id = validador_id
            produto.data_validacao = data_atual
            produto.responsavel_pin = responsavel_pin  # Adicionar o responsável PIN
        
        db.session.commit()
        logger.info(f"Lista validada com sucesso por {validador.nome}, responsável: {responsavel_pin}")
        return True
    
    except Exception as e:
        logger.error(f"Erro ao validar lista: {str(e)}")
        db.session.rollback()
        return False

# Função original mantida para compatibilidade
def validar_lista(data_envio, nome_usuario, validador_id):
    """
    Função legada mantida para compatibilidade
    """
    return validar_lista_com_responsavel(data_envio, nome_usuario, validador_id, "Não especificado")
