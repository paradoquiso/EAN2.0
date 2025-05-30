import sys
import os
from datetime import datetime
import logging
import json
import requests
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file, flash
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
    
    # Verificar se existe o usuário teste
    teste = Usuario.query.filter_by(nome='teste').first()
    if not teste:
        # Criar usuário teste
        hashed_password = generate_password_hash('123')
        teste = Usuario(nome='teste', senha_hash=hashed_password, admin=0)
        db.session.add(teste)
        db.session.commit()
        logger.info("Usuário teste criado com sucesso")

# Rota raiz - redireciona para login
@app.route('/')
def index():
    if 'usuario_id' in session:
        # Se já estiver logado, redireciona para a página principal
        return redirect(url_for('admin' if session.get('admin') else 'index_usuario'))
    # Se não estiver logado, redireciona para a página de login
    return redirect(url_for('login'))

# Rota de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        usuario = Usuario.query.filter_by(nome=username).first()
        
        if usuario and check_password_hash(usuario.senha_hash, password):
            # Login bem-sucedido
            session['usuario_id'] = usuario.id
            session['nome_usuario'] = usuario.nome
            session['admin'] = usuario.admin
            
            logger.info(f"Usuário {username} logado com sucesso")
            
            # Redirecionar para a página apropriada
            if usuario.admin:
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('index_usuario'))
        else:
            error = "Usuário ou senha inválidos"
            logger.warning(f"Tentativa de login falhou para o usuário {username}")
    
    return render_template('login.html', error=error)

# Rota de registro de novos usuários
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validar se as senhas coincidem
        if password != confirm_password:
            error = "As senhas não coincidem"
            return render_template('registro_simples.html', error=error)
        
        # Verificar se o usuário já existe
        usuario_existente = Usuario.query.filter_by(nome=username).first()
        if usuario_existente:
            error = "Nome de usuário já está em uso"
            return render_template('registro_simples.html', error=error)
        
        # Criar novo usuário (não admin por padrão)
        try:
            hashed_password = generate_password_hash(password)
            novo_usuario = Usuario(nome=username, senha_hash=hashed_password, admin=0)
            db.session.add(novo_usuario)
            db.session.commit()
            
            logger.info(f"Novo usuário {username} registrado com sucesso")
            
            # Fazer login automático após o registro
            session['usuario_id'] = novo_usuario.id
            session['nome_usuario'] = novo_usuario.nome
            session['admin'] = novo_usuario.admin
            
            return redirect(url_for('index_usuario'))
        except Exception as e:
            db.session.rollback()
            error = f"Erro ao registrar usuário: {str(e)}"
            logger.error(f"Erro ao registrar usuário {username}: {str(e)}")
    
    return render_template('registro_simples.html', error=error)

# Rota de logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Página inicial para usuários não-admin
@app.route('/usuario')
def index_usuario():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))
    
    # Garantir que produtos seja sempre uma lista, mesmo que vazia
    produtos = []
    
    return render_template('index.html', nome_usuario=session.get('nome_usuario'), produtos=produtos)

# Página de administração
@app.route('/admin')
def admin():
    if 'usuario_id' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    
    # Buscar listas de produtos enviadas
    listas_por_usuario = {}
    
    try:
        # Buscar produtos enviados agrupados por usuário e data de envio
        produtos_enviados = Produto.query.filter_by(enviado=1).all()
        
        # Agrupar produtos por usuário e data de envio
        for produto in produtos_enviados:
            usuario = Usuario.query.get(produto.usuario_id)
            if not usuario:
                continue
                
            nome_usuario = usuario.nome
            data_envio = produto.data_envio
            
            # Adicionar validador se existir
            if produto.validado and produto.validador_id:
                validador = Usuario.query.get(produto.validador_id)
                produto.nome_validador = validador.nome if validador else "Desconhecido"
            
            # Criar chave para o dicionário
            chave = (nome_usuario, data_envio)
            
            if chave not in listas_por_usuario:
                listas_por_usuario[chave] = []
                
            listas_por_usuario[chave].append(produto)
    
    except Exception as e:
        logger.error(f"Erro ao buscar listas de produtos: {str(e)}")
    
    return render_template('admin.html', nome_usuario=session.get('nome_usuario'), listas_por_usuario=listas_por_usuario)

# Funções auxiliares
def buscar_produto_local(ean, usuario_id):
    produto = Produto.query.filter_by(ean=ean, usuario_id=usuario_id).first()
    if produto:
        return produto.to_dict()
    return None

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

# Tratamento de erros
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error="Página não encontrada"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error="Erro interno do servidor"), 500

# Se este arquivo for executado diretamente
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
