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

def buscar_produto_online(ean):
    try:
        # Obter token de acesso para a API do Mercado Livre
        logger.info(f"Iniciando busca para o EAN: {ean}")
        logger.info("Obtendo token de acesso para a API do Mercado Livre")
        
        # Credenciais do Mercado Livre
        client_id = os.environ.get('ML_CLIENT_ID', '7496208333316548')
        client_secret = os.environ.get('ML_CLIENT_SECRET', 'Ue9Uf0RVZM5oDLdVOFXbIlXUTJVbYQXE')
        redirect_uri = os.environ.get('ML_REDIRECT_URI', 'https://ean2-0-aipr.onrender.com/ml-callback')
        
        # Tentar obter token com código de autorização
        logger.info("Solicitando novo token com código de autorização")
        auth_code = os.environ.get('ML_AUTH_CODE', '')
        
        token = None
        
        if auth_code:
            try:
                token_url = "https://api.mercadolibre.com/oauth/token"
                token_data = {
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code": auth_code,
                    "redirect_uri": redirect_uri
                }
                token_response = requests.post(token_url, data=token_data)
                
                if token_response.status_code == 200:
                    token_info = token_response.json()
                    token = token_info.get('access_token')
                    logger.info(f"Token de acesso obtido com sucesso: {token[:5]}...")
                else:
                    logger.error(f"Erro ao obter token de acesso: {token_response.status_code} - {token_response.text}")
            except Exception as e:
                logger.error(f"Exceção ao obter token de acesso: {str(e)}")
        
        # Se não conseguiu com código de autorização, tentar com client_credentials
        if not token:
            logger.info("Tentando método alternativo com client_credentials")
            try:
                token_url = "https://api.mercadolibre.com/oauth/token"
                token_data = {
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret
                }
                token_response = requests.post(token_url, data=token_data)
                
                if token_response.status_code == 200:
                    token_info = token_response.json()
                    token = token_info.get('access_token')
                    logger.info(f"Token de acesso obtido com sucesso via client_credentials: {token[:10]}...")
                else:
                    logger.error(f"Erro ao obter token via client_credentials: {token_response.status_code} - {token_response.text}")
                    return None
            except Exception as e:
                logger.error(f"Exceção ao obter token via client_credentials: {str(e)}")
                return None
        
        # Estratégia 1: Buscar produto usando o endpoint products/search
        logger.info(f"Estratégia 1: Buscando produto com EAN {ean} usando endpoint products/search")
        search_url = f"https://api.mercadolibre.com/sites/MLB/search?q={ean}"
        headers = {"Authorization": f"Bearer {token}"}
        
        response = requests.get(search_url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            results = data.get('results', [])
            
            logger.info(f"Endpoint products/search retornou {len(results)} resultados")
            
            if results:
                produto = results[0]
                nome = produto.get('title', '')
                logger.info(f"Produto encontrado via products/search: {nome}")
                
                # Extrair informações adicionais
                atributos = produto.get('attributes', [])
                cor = ""
                voltagem = ""
                modelo = ""
                
                for attr in atributos:
                    if attr.get('id') == 'COLOR':
                        cor = attr.get('value_name', '')
                    elif attr.get('id') == 'VOLTAGE':
                        voltagem = attr.get('value_name', '')
                    elif attr.get('id') == 'MODEL':
                        modelo = attr.get('value_name', '')
                
                resultado = {
                    'success': True,
                    'nome': nome,
                    'cor': cor,
                    'voltagem': voltagem,
                    'modelo': modelo,
                    'quantidade': 1,
                    'message': 'Informações do produto carregadas com sucesso!'
                }
                
                logger.info(f"Resultado da busca online: {resultado}")
                return resultado
        
        # Se não encontrou com a primeira estratégia, tentar a segunda
        logger.info(f"Estratégia 2: Buscando produto com EAN {ean} usando endpoint items/search")
        search_url = f"https://api.mercadolibre.com/items/search?q={ean}"
        
        response = requests.get(search_url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            items = data.get('results', [])
            
            logger.info(f"Endpoint items/search retornou {len(items)} resultados")
            
            if items:
                item_id = items[0]
                item_url = f"https://api.mercadolibre.com/items/{item_id}"
                
                item_response = requests.get(item_url, headers=headers)
                if item_response.status_code == 200:
                    produto = item_response.json()
                    nome = produto.get('title', '')
                    logger.info(f"Produto encontrado via items/search: {nome}")
                    
                    # Extrair informações adicionais
                    atributos = produto.get('attributes', [])
                    cor = ""
                    voltagem = ""
                    modelo = ""
                    
                    for attr in atributos:
                        if attr.get('id') == 'COLOR':
                            cor = attr.get('value_name', '')
                        elif attr.get('id') == 'VOLTAGE':
                            voltagem = attr.get('value_name', '')
                        elif attr.get('id') == 'MODEL':
                            modelo = attr.get('value_name', '')
                    
                    resultado = {
                        'success': True,
                        'nome': nome,
                        'cor': cor,
                        'voltagem': voltagem,
                        'modelo': modelo,
                        'quantidade': 1,
                        'message': 'Informações do produto carregadas com sucesso!'
                    }
                    
                    logger.info(f"Resultado da busca online: {resultado}")
                    return resultado
        
        # Se chegou aqui, não encontrou o produto
        logger.warning(f"Produto com EAN {ean} não encontrado online")
        return {
            'success': False,
            'message': 'Produto não encontrado'
        }
    
    except Exception as e:
        logger.error(f"Erro ao buscar produto online: {str(e)}")
        return {
            'success': False,
            'message': f'Erro ao buscar produto: {str(e)}'
        }

def carregar_produtos_usuario(usuario_id):
    produtos = Produto.query.filter_by(
        usuario_id=usuario_id,
        enviado=0  # Usar 0 em vez de false
    ).all()
    
    return [produto.to_dict() for produto in produtos]

def carregar_todas_listas_enviadas():
    # Criar o alias para a tabela de validador apenas uma vez
    ValidadorAlias = db.aliased(Usuario, name='validador_alias')
    
    # Buscar produtos enviados junto com o nome do usuário e do validador (se houver)
    produtos = db.session.query(
        Produto, 
        Usuario.nome.label('nome_usuario'),
        db.func.coalesce(ValidadorAlias.nome, '').label('nome_validador')
    ).join(
        Usuario, Produto.usuario_id == Usuario.id
    ).outerjoin(
        ValidadorAlias, Produto.validador_id == ValidadorAlias.id
    ).filter(
        Produto.enviado == 1  # Usar 1 em vez de true
    ).order_by(
        Produto.data_envio.desc()
    ).all()
    
    # Converter para dicionário
    resultado = []
    for produto, nome_usuario, nome_validador in produtos:
        produto_dict = produto.to_dict()
        produto_dict['nome_usuario'] = nome_usuario
        produto_dict['nome_validador'] = nome_validador
        resultado.append(produto_dict)
    
    # Log para depuração
    logger.info(f"carregar_todas_listas_enviadas: Encontrados {len(resultado)} produtos enviados")
    if resultado:
        logger.info(f"Exemplo do primeiro produto: {resultado[0]}")
    
    return resultado

def pesquisar_produtos(termo_pesquisa):
    # Criar o alias para a tabela de validador apenas uma vez
    ValidadorAlias = db.aliased(Usuario, name='validador_alias')
    
    # Buscar produtos que correspondem ao termo de pesquisa
    produtos = db.session.query(
        Produto, 
        Usuario.nome.label('nome_usuario'),
        db.func.coalesce(ValidadorAlias.nome, '').label('nome_validador')
    ).join(
        Usuario, Produto.usuario_id == Usuario.id
    ).outerjoin(
        ValidadorAlias, Produto.validador_id == ValidadorAlias.id
    ).filter(
        Produto.enviado == 1,  # Usar 1 em vez de true
        db.or_(
            Produto.ean.like(f'%{termo_pesquisa}%'),
            Produto.nome.like(f'%{termo_pesquisa}%'),
            Usuario.nome.like(f'%{termo_pesquisa}%')
        )
    ).order_by(
        Produto.data_envio.desc()
    ).all()
    
    # Converter para dicionário
    resultado = []
    for produto, nome_usuario, nome_validador in produtos:
        produto_dict = produto.to_dict()
        produto_dict['nome_usuario'] = nome_usuario
        produto_dict['nome_validador'] = nome_validador
        resultado.append(produto_dict)
    
    return resultado

def enviar_lista_produtos(usuario_id):
    data_envio = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Marcar todos os produtos não enviados como enviados
    produtos = Produto.query.filter_by(
        usuario_id=usuario_id,
        enviado=0  # Usar 0 em vez de false
    ).all()
    
    # Log para depuração
    logger.info(f"enviar_lista_produtos: Encontrados {len(produtos)} produtos para enviar")
    
    if not produtos:
        logger.warning("Nenhum produto encontrado para enviar")
        return None
    
    for produto in produtos:
        produto.enviado = 1  # Usar 1 em vez de true
        produto.data_envio = data_envio
        logger.info(f"Produto {produto.id} ({produto.nome}) marcado como enviado")
    
    try:
        db.session.commit()
        logger.info(f"Commit realizado com sucesso, {len(produtos)} produtos enviados")
        
        # Verificar se os produtos foram realmente atualizados
        produtos_verificacao = Produto.query.filter_by(
            usuario_id=usuario_id,
            enviado=1,
            data_envio=data_envio
        ).all()
        
        logger.info(f"Verificação pós-commit: {len(produtos_verificacao)} produtos encontrados com data_envio={data_envio}")
        
        return data_envio
    except Exception as e:
        logger.error(f"Erro ao fazer commit das alterações: {str(e)}")
        db.session.rollback()
        return None

def validar_lista(data_envio, nome_usuario, validador_id):
    # Obter o ID do usuário pelo nome
    usuario = Usuario.query.filter_by(nome=nome_usuario).first()
    if not usuario:
        return False
    
    usuario_id = usuario.id
    data_validacao = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Marcar todos os produtos da lista como validados
    produtos = Produto.query.filter_by(
        usuario_id=usuario_id,
        data_envio=data_envio,
        enviado=1  # Usar 1 em vez de true
    ).all()
    
    if not produtos:
        return False
    
    for produto in produtos:
        produto.validado = 1  # Usar 1 em vez de true
        produto.validador_id = validador_id
        produto.data_validacao = data_validacao
    
    db.session.commit()
    return True

# Rotas
@app.route('/')
def index():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))
    
    usuario_id = session['usuario_id']
    nome_usuario = session.get('nome_usuario', 'Usuário')
    
    # Carregar produtos do usuário
    produtos = carregar_produtos_usuario(usuario_id)
    
    return render_template('index.html', nome_usuario=nome_usuario, produtos=produtos)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        nome = request.form.get('username')  # Mantido 'username' no form para compatibilidade
        password = request.form.get('password')
        
        usuario = Usuario.query.filter_by(nome=nome).first()
        
        if usuario and check_password_hash(usuario.senha_hash, password):
            session['usuario_id'] = usuario.id
            session['nome_usuario'] = usuario.nome
            session['admin'] = usuario.admin
            
            if usuario.admin:
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Usuário ou senha inválidos')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin')
def admin():
    if 'usuario_id' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    
    nome_usuario = session.get('nome_usuario', 'Administrador')
    termo_pesquisa = request.args.get('q', '')
    
    if termo_pesquisa:
        listas_enviadas = pesquisar_produtos(termo_pesquisa)
    else:
        listas_enviadas = carregar_todas_listas_enviadas()
    
    # Log para depuração
    logger.info(f"Rota /admin: Encontrados {len(listas_enviadas)} produtos enviados")
    
    # Agrupar por usuário e data de envio
    listas_por_usuario = {}
    for produto in listas_enviadas:
        chave = (produto['nome_usuario'], produto['data_envio'])
        if chave not in listas_por_usuario:
            listas_por_usuario[chave] = []
        listas_por_usuario[chave].append(produto)
    
    # Log para depuração
    logger.info(f"Rota /admin: Agrupados em {len(listas_por_usuario)} listas distintas")
    for chave in listas_por_usuario:
        logger.info(f"Lista de {chave[0]} enviada em {chave[1]} contém {len(listas_por_usuario[chave])} produtos")
    
    return render_template('admin.html', nome_usuario=nome_usuario, listas_por_usuario=listas_por_usuario)

@app.route('/api/buscar-produto')
def api_buscar_produto():
    if 'usuario_id' not in session:
        return jsonify({"success": False, "message": "Não autenticado"})
    
    ean = request.args.get('ean')
    if not ean:
        return jsonify({"success": False, "message": "EAN não fornecido"})
    
    # Primeiro, verificar se o produto já existe para este usuário
    usuario_id = session['usuario_id']
    produto_local = buscar_produto_local(ean, usuario_id)
    
    if produto_local:
        # Mapear os campos do produto local para o formato esperado pelo frontend
        return jsonify({
            "success": True,
            "nome": produto_local.get("nome", ""),
            "cor": produto_local.get("cor", ""),
            "voltagem": produto_local.get("voltagem", ""),
            "modelo": produto_local.get("modelo", ""),
            "quantidade": produto_local.get("quantidade", 1),
            "message": "Produto encontrado localmente"
        })
    
    # Se não encontrou localmente, buscar online
    resultado = buscar_produto_online(ean)
    return jsonify(resultado)

@app.route('/api/produtos', methods=['GET', 'POST', 'DELETE'])
def api_produtos():
    if 'usuario_id' not in session:
        return jsonify({"success": False, "message": "Não autenticado"})
    
    usuario_id = session['usuario_id']
    
    if request.method == 'GET':
        produtos = carregar_produtos_usuario(usuario_id)
        return jsonify({
            "success": True,
            "produtos": produtos
        })
    
    elif request.method == 'POST':
        dados = request.json
        
        if not dados or not dados.get('ean') or not dados.get('nome'):
            return jsonify({
                "success": False,
                "message": "Dados incompletos"
            })
        
        # Verificar se o produto já existe
        produto_existente = Produto.query.filter_by(
            ean=dados['ean'],
            usuario_id=usuario_id,
            enviado=0  # Usar 0 em vez de false
        ).first()
        
        if produto_existente:
            # Atualizar produto existente
            produto_existente.nome = dados['nome']
            produto_existente.cor = dados.get('cor', '')
            produto_existente.voltagem = dados.get('voltagem', '')
            produto_existente.modelo = dados.get('modelo', '')
            produto_existente.quantidade = dados.get('quantidade', 1)
            produto_existente.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        else:
            # Criar novo produto
            novo_produto = Produto(
                ean=dados['ean'],
                nome=dados['nome'],
                cor=dados.get('cor', ''),
                voltagem=dados.get('voltagem', ''),
                modelo=dados.get('modelo', ''),
                quantidade=dados.get('quantidade', 1),
                usuario_id=usuario_id,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                enviado=0  # Usar 0 em vez de false
            )
            db.session.add(novo_produto)
        
        db.session.commit()
        
        # Retornar a lista atualizada de produtos
        produtos = carregar_produtos_usuario(usuario_id)
        return jsonify({
            "success": True,
            "message": "Produto adicionado com sucesso",
            "produtos": produtos
        })
    
    elif request.method == 'DELETE':
        return jsonify({
            "success": False,
            "message": "Método DELETE não implementado nesta rota"
        })

@app.route('/api/produtos/<int:produto_id>', methods=['DELETE'])
def api_produto_delete(produto_id):
    if 'usuario_id' not in session:
        return jsonify({"success": False, "message": "Não autenticado"})
    
    usuario_id = session['usuario_id']
    
    # Buscar o produto
    produto = Produto.query.filter_by(id=produto_id, usuario_id=usuario_id).first()
    
    if not produto:
        return jsonify({
            "success": False,
            "message": "Produto não encontrado"
        })
    
    # Verificar se o produto já foi enviado
    if produto.enviado == 1:  # Usar 1 em vez de true
        return jsonify({
            "success": False,
            "message": "Não é possível excluir um produto já enviado"
        })
    
    # Excluir o produto
    db.session.delete(produto)
    db.session.commit()
    
    # Retornar a lista atualizada de produtos
    produtos = carregar_produtos_usuario(usuario_id)
    return jsonify({
        "success": True,
        "message": "Produto removido com sucesso",
        "produtos": produtos
    })

@app.route('/api/enviar-lista', methods=['POST'])
def api_enviar_lista():
    if 'usuario_id' not in session:
        return jsonify({"success": False, "message": "Não autenticado"})
    
    usuario_id = session['usuario_id']
    
    # Log para depuração
    logger.info(f"Iniciando envio de lista para o usuário {usuario_id}")
    
    data_envio = enviar_lista_produtos(usuario_id)
    
    if data_envio:
        logger.info(f"Lista enviada com sucesso, data_envio: {data_envio}")
        return jsonify({
            "success": True,
            "message": "Lista enviada com sucesso",
            "data_envio": data_envio
        })
    else:
        logger.error("Erro ao enviar lista ou nenhum produto para enviar")
        return jsonify({
            "success": False,
            "message": "Erro ao enviar lista ou nenhum produto para enviar"
        })

@app.route('/api/validar-lista', methods=['POST'])
def api_validar_lista():
    if 'usuario_id' not in session or not session.get('admin'):
        return jsonify({"success": False, "message": "Não autorizado"})
    
    dados = request.json
    if not dados or 'nome_usuario' not in dados or 'data_envio' not in dados:
        return jsonify({"success": False, "message": "Dados incompletos"})
    
    validador_id = session['usuario_id']
    if validar_lista(dados['data_envio'], dados['nome_usuario'], validador_id):
        return jsonify({
            "success": True,
            "message": "Lista validada com sucesso"
        })
    else:
        return jsonify({
            "success": False,
            "message": "Erro ao validar lista"
        })

@app.route('/api/export')
def api_export():
    if 'usuario_id' not in session:
        return jsonify({"success": False, "message": "Não autenticado"})
    
    usuario_id = session['usuario_id']
    
    # Buscar produtos não enviados do usuário
    produtos = Produto.query.filter_by(
        usuario_id=usuario_id,
        enviado=0  # Usar 0 em vez de false
    ).all()
    
    # Converter para DataFrame
    data = []
    for produto in produtos:
        data.append({
            'EAN': produto.ean,
            'Nome': produto.nome,
            'Cor': produto.cor,
            'Voltagem': produto.voltagem,
            'Modelo': produto.modelo,
            'Quantidade': produto.quantidade
        })
    
    df = pd.DataFrame(data)
    
    # Criar arquivo Excel em memória
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Produtos')
    
    output.seek(0)
    
    # Gerar nome do arquivo com timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"produtos_{timestamp}.xlsx"
    
    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

@app.route('/ml-callback')
def ml_callback():
    code = request.args.get('code')
    if code:
        # Salvar o código de autorização
        os.environ['ML_AUTH_CODE'] = code
        return "Autorização concedida com sucesso! Você pode fechar esta janela."
    else:
        return "Erro ao obter código de autorização."

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
