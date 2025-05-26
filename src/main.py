"""
Arquivo principal da aplicação EAN.
Implementa todas as rotas e funcionalidades do sistema.
Adaptado para uso com PostgreSQL no Render.
"""

import os
import sys
from datetime import datetime
import io
import requests
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, flash
import pandas as pd
import json
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Adicionar o diretório raiz ao path para importar módulos
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Importar configuração do banco de dados
from db_config import configure_db
from src.models.models import Usuario, Produto, init_database

app = Flask(__name__)
app.secret_key = 'ean_app_secret_key'  # Chave para sessões

# Configuração do login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configurar o banco de dados
db = configure_db(app)

@login_manager.user_loader
def load_user(user_id):
    """
    Carrega um usuário pelo ID para o Flask-Login.
    """
    return Usuario.query.get(int(user_id))

# Funções de autenticação
def registrar_usuario(nome, senha, admin=0):
    """
    Registra um novo usuário no banco de dados.
    """
    try:
        usuario = Usuario(nome=nome, senha=senha, admin=admin)
        db.session.add(usuario)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"Erro ao registrar usuário: {str(e)}")
        return False

def verificar_usuario(nome, senha):
    """
    Verifica as credenciais do usuário.
    """
    usuario = Usuario.query.filter_by(nome=nome).first()
    
    if usuario and usuario.verificar_senha(senha):
        return usuario
    
    return None

def obter_nome_usuario(usuario_id):
    """
    Obtém o nome de um usuário pelo ID.
    """
    usuario = Usuario.query.get(usuario_id)
    return usuario.nome if usuario else None

# Funções de produtos
def carregar_produtos_usuario(usuario_id, apenas_nao_enviados=False):
    """
    Carrega os produtos de um usuário específico.
    """
    query = Produto.query.filter_by(usuario_id=usuario_id)
    
    if apenas_nao_enviados:
        query = query.filter_by(enviado=0)
    
    produtos = query.all()
    return [produto.to_dict() for produto in produtos]

def carregar_todas_listas_enviadas():
    """
    Carrega todas as listas de produtos enviadas.
    """
    produtos = db.session.query(
        Produto, 
        Usuario.nome.label('nome_usuario'),
        db.func.coalesce(db.aliased(Usuario, name='validador').nome, '').label('nome_validador')
    ).join(
        Usuario, Produto.usuario_id == Usuario.id
    ).outerjoin(
        db.aliased(Usuario, name='validador'), Produto.validador_id == db.aliased(Usuario, name='validador').id
    ).filter(
        Produto.enviado == 1
    ).order_by(
        Produto.data_envio.desc()
    ).all()
    
    resultado = []
    for produto, nome_usuario, nome_validador in produtos:
        produto_dict = produto.to_dict()
        produto_dict['nome_usuario'] = nome_usuario
        produto_dict['nome_validador'] = nome_validador
        resultado.append(produto_dict)
    
    return resultado

def pesquisar_produtos(termo_pesquisa):
    """
    Pesquisa produtos por termo.
    """
    termo = f"%{termo_pesquisa}%"
    
    produtos = db.session.query(
        Produto, 
        Usuario.nome.label('nome_usuario'),
        db.func.coalesce(db.aliased(Usuario, name='validador').nome, '').label('nome_validador')
    ).join(
        Usuario, Produto.usuario_id == Usuario.id
    ).outerjoin(
        db.aliased(Usuario, name='validador'), Produto.validador_id == db.aliased(Usuario, name='validador').id
    ).filter(
        Produto.enviado == 1,
        db.or_(
            Produto.ean.ilike(termo),
            Produto.nome.ilike(termo),
            Produto.cor.ilike(termo),
            Produto.modelo.ilike(termo)
        )
    ).order_by(
        Produto.data_envio.desc()
    ).all()
    
    resultado = []
    for produto, nome_usuario, nome_validador in produtos:
        produto_dict = produto.to_dict()
        produto_dict['nome_usuario'] = nome_usuario
        produto_dict['nome_validador'] = nome_validador
        resultado.append(produto_dict)
    
    return resultado

def buscar_produto_local(ean, usuario_id):
    """
    Busca um produto local pelo EAN e ID do usuário.
    """
    produto = Produto.query.filter_by(
        ean=ean, 
        usuario_id=usuario_id,
        enviado=0
    ).first()
    
    return produto.to_dict() if produto else None

def salvar_produto(produto_data, usuario_id):
    """
    Salva um produto no banco de dados.
    """
    try:
        # Verificar se o produto já existe para este usuário e não foi enviado
        produto_existente = Produto.query.filter_by(
            ean=produto_data['ean'], 
            usuario_id=usuario_id,
            enviado=0
        ).first()
        
        if produto_existente:
            # Atualizar quantidade
            produto_existente.quantidade += produto_data['quantidade']
            produto_existente.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        else:
            # Criar novo produto
            produto = Produto(
                ean=produto_data['ean'],
                nome=produto_data['nome'],
                cor=produto_data.get('cor', ''),
                voltagem=produto_data.get('voltagem', ''),
                modelo=produto_data.get('modelo', ''),
                quantidade=produto_data['quantidade'],
                usuario_id=usuario_id
            )
            db.session.add(produto)
        
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"Erro ao salvar produto: {str(e)}")
        return False

def enviar_lista_produtos(usuario_id):
    """
    Marca todos os produtos não enviados de um usuário como enviados.
    """
    try:
        data_envio = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        produtos = Produto.query.filter_by(
            usuario_id=usuario_id,
            enviado=0
        ).all()
        
        for produto in produtos:
            produto.enviado = 1
            produto.data_envio = data_envio
        
        db.session.commit()
        return data_envio
    except Exception as e:
        db.session.rollback()
        print(f"Erro ao enviar lista: {str(e)}")
        return None

def validar_lista(data_envio, nome_usuario, validador_id):
    """
    Valida uma lista de produtos.
    """
    try:
        # Obter o ID do usuário pelo nome
        usuario = Usuario.query.filter_by(nome=nome_usuario).first()
        
        if not usuario:
            return False
        
        data_validacao = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Marcar todos os produtos da lista como validados
        produtos = Produto.query.filter_by(
            usuario_id=usuario.id,
            data_envio=data_envio,
            enviado=1
        ).all()
        
        for produto in produtos:
            produto.validado = 1
            produto.validador_id = validador_id
            produto.data_validacao = data_validacao
        
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"Erro ao validar lista: {str(e)}")
        return False

def excluir_produto(produto_id, usuario_id):
    """
    Exclui um produto do banco de dados.
    """
    try:
        produto = Produto.query.filter_by(
            id=produto_id,
            usuario_id=usuario_id,
            enviado=0
        ).first()
        
        if produto:
            db.session.delete(produto)
            db.session.commit()
            return True
        
        return False
    except Exception as e:
        db.session.rollback()
        print(f"Erro ao excluir produto: {str(e)}")
        return False

# Importar o módulo de busca do Mercado Livre
try:
    from src.mercado_livre import buscar_produto_por_ean
except ImportError:
    # Função de fallback se o módulo não estiver disponível
    def buscar_produto_por_ean(ean):
        return {"success": False, "message": "Módulo de busca do Mercado Livre não disponível"}

# Função para buscar informações do produto por EAN online
def buscar_produto_online(ean):
    try:
        # Primeiro, tentamos buscar no Mercado Livre
        resultado_ml = buscar_produto_por_ean(ean)
        if resultado_ml and resultado_ml.get("success"):
            return resultado_ml
        
        # Se não encontrar no Mercado Livre, tentamos a API alternativa
        token_url = "https://gtin.rscsistemas.com.br/oauth/token"
        token_response = requests.post(token_url, json={
            "username": "demo",  # Usuário demo para testes
            "password": "demo"   # Senha demo para testes
        }, timeout=5)
        
        if token_response.status_code != 200:
            # Se não conseguir autenticar, retornamos dados básicos para edição manual
            return {
                "success": True,
                "data": {
                    "nome": f"Produto {ean}",
                    "marca": "",
                    "categoria": ""
                },
                "message": "Produto não encontrado na base de dados. Por favor, preencha as informações manualmente."
            }
        
        token_data = token_response.json()
        token = token_data.get("token")
        
        # Com o token, buscamos as informações do produto
        produto_url = f"https://gtin.rscsistemas.com.br/api/gtin/infor/{ean}"
        headers = {"Authorization": f"Bearer {token}"}
        produto_response = requests.get(produto_url, headers=headers, timeout=5)
        
        if produto_response.status_code == 200:
            produto_data = produto_response.json()
            # Verificar se o produto foi realmente encontrado ou se é uma resposta padrão de "não encontrado"
            if produto_data.get("nome") == "405" or produto_data.get("ean") == "405":
                return {
                    "success": True,
                    "data": {
                        "nome": f"Produto {ean}",
                        "marca": "",
                        "categoria": ""
                    },
                    "message": "Produto não encontrado na base de dados. Por favor, preencha as informações manualmente."
                }
            return {
                "success": True,
                "data": produto_data
            }
        else:
            # Se não encontrar na API, retornamos dados básicos para edição manual
            return {
                "success": True,
                "data": {
                    "nome": f"Produto {ean}",
                    "marca": "",
                    "categoria": ""
                },
                "message": "Produto não encontrado na base de dados. Por favor, preencha as informações manualmente."
            }
    except Exception as e:
        # Em caso de erro, retornamos dados básicos para edição manual
        return {
            "success": True,
            "data": {
                "nome": f"Produto {ean}",
                "marca": "",
                "categoria": ""
            },
            "message": f"Erro ao buscar produto: {str(e)}. Por favor, preencha as informações manualmente."
        }

# Rotas de autenticação
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        nome = request.form.get('nome')
        senha = request.form.get('senha')
        
        usuario = verificar_usuario(nome, senha)
        if usuario:
            # Fazer login com Flask-Login
            login_user(usuario)
            
            # Armazenar informações na sessão
            session['logado'] = True
            session['usuario_id'] = usuario.id
            session['usuario_nome'] = usuario.nome
            session['admin'] = usuario.admin
            
            if usuario.admin:
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('index'))
        else:
            flash('Nome de usuário ou senha incorretos')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nome = request.form.get('nome')
        senha = request.form.get('senha')
        
        if registrar_usuario(nome, senha):
            flash('Usuário registrado com sucesso! Faça login para continuar.')
            return redirect(url_for('login'))
        else:
            flash('Nome de usuário já existe')
    
    return render_template('registro.html')

# Rotas da aplicação
@app.route('/')
@login_required
def index():
    produtos = carregar_produtos_usuario(current_user.id, apenas_nao_enviados=True)
    return render_template('index.html', produtos=produtos)

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.admin:
        return redirect(url_for('login'))
    
    termo_pesquisa = request.args.get('pesquisa', '')
    
    if termo_pesquisa:
        # Se houver termo de pesquisa, buscar produtos correspondentes
        produtos_encontrados = pesquisar_produtos(termo_pesquisa)
        
        # Agrupar produtos por data de envio e usuário
        listas_agrupadas = {}
        for produto in produtos_encontrados:
            chave = (produto['data_envio'], produto['nome_usuario'])
            if chave not in listas_agrupadas:
                listas_agrupadas[chave] = {
                    'produtos': [],
                    'validado': produto.get('validado', 0),
                    'nome_validador': produto.get('nome_validador', None),
                    'data_validacao': produto.get('data_validacao', None)
                }
            listas_agrupadas[chave]['produtos'].append(produto)
        
        return render_template('admin.html', listas_agrupadas=listas_agrupadas, termo_pesquisa=termo_pesquisa)
    else:
        # Se não houver pesquisa, mostrar todas as listas
        listas_enviadas = carregar_todas_listas_enviadas()
        
        # Agrupar produtos por data de envio e usuário
        listas_agrupadas = {}
        for produto in listas_enviadas:
            chave = (produto['data_envio'], produto['nome_usuario'])
            if chave not in listas_agrupadas:
                listas_agrupadas[chave] = {
                    'produtos': [],
                    'validado': produto.get('validado', 0),
                    'nome_validador': produto.get('nome_validador', None),
                    'data_validacao': produto.get('data_validacao', None)
                }
            listas_agrupadas[chave]['produtos'].append(produto)
        
        return render_template('admin.html', listas_agrupadas=listas_agrupadas, termo_pesquisa='')

@app.route('/api/buscar-produto', methods=['GET'])
@login_required
def buscar_produto():
    ean = request.args.get('ean')
    if not ean:
        return jsonify({"error": "EAN não fornecido"}), 400
    
    # Primeiro, verificar se o produto já existe no banco de dados local
    produto_local = buscar_produto_local(ean, current_user.id)
    if produto_local:
        return jsonify({
            "ean": produto_local['ean'],
            "nome": produto_local['nome'],
            "cor": produto_local['cor'],
            "voltagem": produto_local['voltagem'],
            "modelo": produto_local['modelo'],
            "quantidade": produto_local['quantidade'],
            "message": "Produto encontrado no banco de dados local."
        }), 200
    
    # Se não existir localmente, buscar online
    resultado = buscar_produto_online(ean)
    
    if resultado["success"]:
        produto_data = resultado["data"]
        
        # Extrair informações relevantes
        nome = produto_data.get("nome", f"Produto {ean}")
        cor = produto_data.get("cor", "")
        voltagem = produto_data.get("voltagem", "")
        modelo = produto_data.get("modelo", "")
        
        return jsonify({
            "ean": ean,
            "nome": nome,
            "cor": cor,
            "voltagem": voltagem,
            "modelo": modelo,
            "quantidade": 1,
            "message": resultado.get("message", "Produto encontrado.")
        }), 200
    else:
        return jsonify({
            "ean": ean,
            "nome": f"Produto {ean}",
            "cor": "",
            "voltagem": "",
            "modelo": "",
            "quantidade": 1,
            "message": resultado.get("message", "Produto não encontrado. Por favor, preencha as informações manualmente.")
        }), 200

@app.route('/api/produtos', methods=['POST'])
@login_required
def adicionar_produto():
    try:
        dados = request.json
        ean = dados.get('ean')
        nome = dados.get('nome')
        cor = dados.get('cor', '')
        voltagem = dados.get('voltagem', '')
        modelo = dados.get('modelo', '')
        quantidade = dados.get('quantidade', 1)
        
        if not ean or not nome:
            return jsonify({"erro": "EAN e nome são obrigatórios"}), 400
        
        produto_data = {
            'ean': ean,
            'nome': nome,
            'cor': cor,
            'voltagem': voltagem,
            'modelo': modelo,
            'quantidade': quantidade,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        if salvar_produto(produto_data, current_user.id):
            return jsonify({"sucesso": True, "mensagem": "Produto adicionado com sucesso"}), 200
        else:
            return jsonify({"erro": "Erro ao adicionar produto"}), 500
    
    except Exception as e:
        print(f"Erro ao adicionar produto: {str(e)}")
        return jsonify({"erro": f"Erro ao adicionar produto: {str(e)}"}), 500

@app.route('/enviar-lista', methods=['POST'])
@login_required
def enviar_lista():
    data_envio = enviar_lista_produtos(current_user.id)
    
    if data_envio:
        flash(f'Lista enviada com sucesso em {data_envio}')
    else:
        flash('Erro ao enviar lista')
    
    return redirect(url_for('index'))

@app.route('/validar-lista', methods=['POST'])
@login_required
def validar_lista_rota():
    if not current_user.admin:
        return redirect(url_for('login'))
    
    data_envio = request.form.get('data_envio')
    nome_usuario = request.form.get('nome_usuario')
    
    if validar_lista(data_envio, nome_usuario, current_user.id):
        flash(f'Lista de {nome_usuario} validada com sucesso')
    else:
        flash('Erro ao validar lista')
    
    return redirect(url_for('admin_panel'))

@app.route('/excluir-produto/<int:produto_id>', methods=['POST'])
@login_required
def excluir_produto_rota(produto_id):
    if excluir_produto(produto_id, current_user.id):
        flash('Produto excluído com sucesso')
    else:
        flash('Erro ao excluir produto')
    
    return redirect(url_for('index'))

# Inicializar o banco de dados
with app.app_context():
    init_database(app)

if __name__ == '__main__':
    app.run(debug=True)
