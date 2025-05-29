import sys
import os
from datetime import datetime
import io
import requests
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, flash
import pandas as pd
import json
import logging
from werkzeug.security import generate_password_hash, check_password_hash

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Importar configurações e banco de dados
from src.config import get_config
from src.database import db, init_db
from src.models.usuario import Usuario
from src.models.produto import Produto

# Importar o módulo de busca do Mercado Livre
from src.mercado_livre import buscar_produto_por_ean

# Inicializar aplicação Flask
app = Flask(__name__)
app.config.from_object(get_config())

# Inicializar banco de dados
init_db(app)

# Funções de autenticação
def registrar_usuario(nome, senha):
    try:
        senha_hash = generate_password_hash(senha)
        novo_usuario = Usuario(nome=nome, senha_hash=senha_hash)
        db.session.add(novo_usuario)
        db.session.commit()
        return True
    except Exception:
        # Nome de usuário já existe ou outro erro
        db.session.rollback()
        return False

def verificar_usuario(nome, senha):
    usuario = Usuario.query.filter_by(nome=nome).first()
    if usuario and check_password_hash(usuario.senha_hash, senha):
        return {'id': usuario.id, 'admin': usuario.admin}
    return None

def obter_nome_usuario(usuario_id):
    usuario = Usuario.query.get(usuario_id)
    return usuario.nome if usuario else None

# Funções de produtos
def carregar_produtos_usuario(usuario_id, apenas_nao_enviados=False):
    query = Produto.query.filter_by(usuario_id=usuario_id)
    if apenas_nao_enviados:
        query = query.filter_by(enviado=0)
    produtos = query.all()
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
    
    return resultado

def pesquisar_produtos(termo_pesquisa):
    # Criar o alias para a tabela de validador apenas uma vez
    ValidadorAlias = db.aliased(Usuario, name='validador_alias')
    
    # Buscar produtos que correspondem ao termo de pesquisa (EAN ou palavra na descrição)
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
            Produto.ean.ilike(f'%{termo_pesquisa}%'),
            Produto.nome.ilike(f'%{termo_pesquisa}%'),
            Produto.cor.ilike(f'%{termo_pesquisa}%'),
            Produto.modelo.ilike(f'%{termo_pesquisa}%')
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

def buscar_produto_local(ean, usuario_id):
    produto = Produto.query.filter_by(
        ean=ean,
        usuario_id=usuario_id,
        enviado=0  # Usar 0 em vez de false
    ).first()
    
    if produto:
        return produto.to_dict()
    return None

def salvar_produto(produto, usuario_id):
    # Verificar se o produto já existe para este usuário e não foi enviado
    produto_existente = Produto.query.filter_by(
        ean=produto['ean'],
        usuario_id=usuario_id,
        enviado=0  # Usar 0 em vez de false
    ).first()
    
    try:
        if produto_existente:
            # Atualizar quantidade
            produto_existente.quantidade += produto['quantidade']
            produto_existente.timestamp = produto['timestamp']
        else:
            # Inserir novo produto
            novo_produto = Produto(
                ean=produto['ean'],
                nome=produto['nome'],
                cor=produto['cor'],
                voltagem=produto['voltagem'],
                modelo=produto['modelo'],
                quantidade=produto['quantidade'],
                usuario_id=usuario_id,
                timestamp=produto['timestamp'],
                enviado=0  # Usar 0 em vez de false
            )
            db.session.add(novo_produto)
        
        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        return False

def enviar_lista_produtos(usuario_id):
    data_envio = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Marcar todos os produtos não enviados como enviados
    produtos = Produto.query.filter_by(
        usuario_id=usuario_id,
        enviado=0  # Usar 0 em vez de false
    ).all()
    
    for produto in produtos:
        produto.enviado = 1  # Usar 1 em vez de true
        produto.data_envio = data_envio
    
    db.session.commit()
    return data_envio

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
    
    for produto in produtos:
        produto.validado = 1  # Usar 1 em vez de true
        produto.validador_id = validador_id
        produto.data_validacao = data_validacao
    
    db.session.commit()
    return True

def excluir_produto(produto_id, usuario_id):
    produto = Produto.query.filter_by(
        id=produto_id,
        usuario_id=usuario_id,
        enviado=0  # Usar 0 em vez de false
    ).first()
    
    if produto:
        db.session.delete(produto)
        db.session.commit()
        return True
    return False

# Função para buscar informações do produto por EAN online
def buscar_produto_online(ean):
    try:
        # Primeiro, tentamos buscar no Mercado Livre
        resultado_ml = buscar_produto_por_ean(ean)
        if resultado_ml and resultado_ml.get("success"):
            # Extrair os dados do produto para o formato esperado pelo frontend
            produto_data = resultado_ml.get("data", {})
            
            # Mapear os campos do resultado para o formato esperado pelo frontend
            return {
                "success": True,
                "nome": produto_data.get("nome", f"Produto {ean}"),
                "cor": produto_data.get("cor", ""),
                "voltagem": produto_data.get("voltagem", ""),
                "modelo": produto_data.get("modelo", ""),
                "quantidade": 1,
                "message": "Informações do produto carregadas com sucesso!"
            }
        
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
                "nome": f"Produto {ean}",
                "cor": "",
                "voltagem": "",
                "modelo": "",
                "quantidade": 1,
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
                    "nome": f"Produto {ean}",
                    "cor": "",
                    "voltagem": "",
                    "modelo": "",
                    "quantidade": 1,
                    "message": "Produto não encontrado na base de dados. Por favor, preencha as informações manualmente."
                }
            
            return {
                "success": True,
                "nome": produto_data.get("nome", f"Produto {ean}"),
                "cor": produto_data.get("cor", ""),
                "voltagem": produto_data.get("voltagem", ""),
                "modelo": produto_data.get("modelo", ""),
                "quantidade": 1,
                "message": "Informações do produto carregadas com sucesso!"
            }
        else:
            # Se não encontrar na API, retornamos dados básicos para edição manual
            return {
                "success": True,
                "nome": f"Produto {ean}",
                "cor": "",
                "voltagem": "",
                "modelo": "",
                "quantidade": 1,
                "message": "Produto não encontrado na base de dados. Por favor, preencha as informações manualmente."
            }
    except Exception as e:
        logger.error(f"Erro ao buscar produto: {str(e)}")
        # Em caso de erro, retornamos dados básicos para edição manual
        return {
            "success": True,
            "nome": f"Produto {ean}",
            "cor": "",
            "voltagem": "",
            "modelo": "",
            "quantidade": 1,
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
            session['usuario_id'] = usuario['id']
            session['admin'] = usuario['admin']
            
            if usuario['admin']:
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('index'))
        else:
            flash('Nome de usuário ou senha incorretos')
    
    return render_template('login.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nome = request.form.get('nome')
        senha = request.form.get('senha')
        
        if registrar_usuario(nome, senha):
            flash('Usuário registrado com sucesso! Faça login para continuar.')
            return redirect(url_for('login'))
        else:
            flash('Erro ao registrar usuário. Nome de usuário já existe ou ocorreu um erro.')
    
    return render_template('registro.html')

@app.route('/logout')
def logout():
    session.pop('usuario_id', None)
    session.pop('admin', None)
    return redirect(url_for('login'))

# Rotas principais
@app.route('/')
def index():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))
    
    if session.get('admin'):
        return redirect(url_for('admin_panel'))
    
    usuario_id = session['usuario_id']
    nome_usuario = obter_nome_usuario(usuario_id)
    produtos = carregar_produtos_usuario(usuario_id, apenas_nao_enviados=True)
    
    return render_template('index.html', nome_usuario=nome_usuario, produtos=produtos)

@app.route('/admin')
def admin_panel():
    if 'usuario_id' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    
    usuario_id = session['usuario_id']
    nome_usuario = obter_nome_usuario(usuario_id)
    listas_enviadas = carregar_todas_listas_enviadas()
    
    # Agrupar por usuário e data de envio
    listas_por_usuario = {}
    for produto in listas_enviadas:
        chave = (produto['nome_usuario'], produto['data_envio'])
        if chave not in listas_por_usuario:
            listas_por_usuario[chave] = []
        listas_por_usuario[chave].append(produto)
    
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
    
    # Se não existir localmente, buscar online
    resultado = buscar_produto_online(ean)
    logger.info(f"Resultado da busca online: {resultado}")
    return jsonify(resultado)

@app.route('/api/produtos', methods=['POST'])
def api_adicionar_produto():
    if 'usuario_id' not in session:
        return jsonify({"success": False, "message": "Não autenticado"})
    
    dados = request.json
    if not dados:
        return jsonify({"success": False, "message": "Dados não fornecidos"})
    
    # Adicionar timestamp
    dados['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Salvar produto
    usuario_id = session['usuario_id']
    if salvar_produto(dados, usuario_id):
        # Recarregar produtos
        produtos = carregar_produtos_usuario(usuario_id, apenas_nao_enviados=True)
        return jsonify({
            "success": True,
            "message": "Produto adicionado com sucesso",
            "produtos": produtos
        })
    else:
        return jsonify({
            "success": False,
            "message": "Erro ao adicionar produto"
        })

@app.route('/api/produtos/<int:produto_id>', methods=['DELETE'])
def api_excluir_produto(produto_id):
    if 'usuario_id' not in session:
        return jsonify({"success": False, "message": "Não autenticado"})
    
    usuario_id = session['usuario_id']
    if excluir_produto(produto_id, usuario_id):
        # Recarregar produtos
        produtos = carregar_produtos_usuario(usuario_id, apenas_nao_enviados=True)
        return jsonify({
            "success": True,
            "message": "Produto excluído com sucesso",
            "produtos": produtos
        })
    else:
        return jsonify({
            "success": False,
            "message": "Erro ao excluir produto"
        })

@app.route('/api/enviar-lista', methods=['POST'])
def api_enviar_lista():
    if 'usuario_id' not in session:
        return jsonify({"success": False, "message": "Não autenticado"})
    
    usuario_id = session['usuario_id']
    data_envio = enviar_lista_produtos(usuario_id)
    
    if data_envio:
        return jsonify({
            "success": True,
            "message": "Lista enviada com sucesso",
            "data_envio": data_envio
        })
    else:
        return jsonify({
            "success": False,
            "message": "Erro ao enviar lista"
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

@app.route('/api/pesquisar', methods=['GET'])
def api_pesquisar():
    if 'usuario_id' not in session or not session.get('admin'):
        return jsonify({"success": False, "message": "Não autorizado"})
    
    termo = request.args.get('termo')
    if not termo:
        return jsonify({"success": False, "message": "Termo de pesquisa não fornecido"})
    
    resultados = pesquisar_produtos(termo)
    return jsonify({
        "success": True,
        "resultados": resultados
    })

@app.route('/api/exportar-excel', methods=['POST'])
def api_exportar_excel():
    if 'usuario_id' not in session or not session.get('admin'):
        return jsonify({"success": False, "message": "Não autorizado"}, 403)
    
    dados = request.json
    if not dados or 'produtos' not in dados:
        return jsonify({"success": False, "message": "Dados incompletos"}, 400)
    
    produtos = dados['produtos']
    
    # Criar DataFrame
    df = pd.DataFrame([
        {
            'EAN': p['ean'],
            'DESCRIÇÃO': p['nome'],
            'QUANTIDADE': p['quantidade']
        }
        for p in produtos
    ])
    
    # Criar arquivo Excel em memória
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False)
    
    output.seek(0)
    
    # Gerar nome do arquivo
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"produtos_{timestamp}.xlsx"
    
    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
