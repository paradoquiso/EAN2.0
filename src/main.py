import sys
import os
from datetime import datetime
import io
import requests
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, flash
import pandas as pd
import json
from werkzeug.security import generate_password_hash, check_password_hash

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
    # Buscar produtos enviados junto com o nome do usuário e do validador (se houver)
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
    
    # Converter para dicionário
    resultado = []
    for produto, nome_usuario, nome_validador in produtos:
        produto_dict = produto.to_dict()
        produto_dict['nome_usuario'] = nome_usuario
        produto_dict['nome_validador'] = nome_validador
        resultado.append(produto_dict)
    
    return resultado

def pesquisar_produtos(termo_pesquisa):
    # Buscar produtos que correspondem ao termo de pesquisa (EAN ou palavra na descrição)
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
        enviado=0
    ).first()
    
    if produto:
        return produto.to_dict()
    return None

def salvar_produto(produto, usuario_id):
    # Verificar se o produto já existe para este usuário e não foi enviado
    produto_existente = Produto.query.filter_by(
        ean=produto['ean'], 
        usuario_id=usuario_id, 
        enviado=0
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
                enviado=0
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
        enviado=0
    ).all()
    
    for produto in produtos:
        produto.enviado = 1
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
        enviado=1
    ).all()
    
    for produto in produtos:
        produto.validado = 1
        produto.validador_id = validador_id
        produto.data_validacao = data_validacao
    
    db.session.commit()
    return True

def excluir_produto(produto_id, usuario_id):
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
            session['usuario_id'] = usuario['id']
            session['usuario_nome'] = nome
            session['admin'] = usuario['admin']
            
            if usuario['admin']:
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('index'))
        else:
            flash('Nome de usuário ou senha incorretos')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
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
def index():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))
    
    produtos = carregar_produtos_usuario(session['usuario_id'], apenas_nao_enviados=True)
    return render_template('index.html', produtos=produtos)

@app.route('/admin')
def admin_panel():
    if 'usuario_id' not in session or not session.get('admin'):
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
def buscar_produto():
    if 'usuario_id' not in session:
        return jsonify({"error": "Não autorizado"}), 401
    
    ean = request.args.get('ean')
    if not ean:
        return jsonify({"error": "EAN não fornecido"}), 400
    
    # Primeiro, verificar se o produto já existe no banco de dados local
    produto_local = buscar_produto_local(ean, session['usuario_id'])
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
        marca = produto_data.get("marca", "")
        
        # Retornar as informações obtidas com todos os campos disponíveis
        return jsonify({
            "ean": ean,
            "nome": nome,
            "cor": cor,
            "voltagem": voltagem,
            "modelo": modelo,
            "quantidade": 1,
            "message": resultado.get("message", "")
        }), 200
    else:
        return jsonify({
            "error": "Produto não encontrado",
            "ean": ean,
            "nome": f"Produto {ean}",
            "cor": "",
            "voltagem": "",
            "modelo": "",
            "quantidade": 1,
            "message": "Produto não encontrado. Por favor, preencha as informações manualmente."
        }), 200

@app.route('/api/produtos', methods=['GET'])
def get_produtos():
    if 'usuario_id' not in session:
        return jsonify({"error": "Não autorizado"}), 401
    
    produtos = carregar_produtos_usuario(session['usuario_id'], apenas_nao_enviados=True)
    return jsonify(produtos)

@app.route('/api/produtos', methods=['POST'])
def add_produto():
    if 'usuario_id' not in session:
        return jsonify({"error": "Não autorizado"}), 401
    
    data = request.json
    
    # Adicionar timestamp
    data['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Salvar no banco de dados
    salvar_produto(data, session['usuario_id'])
    
    # Retornar os produtos atualizados
    produtos = carregar_produtos_usuario(session['usuario_id'], apenas_nao_enviados=True)
    return jsonify(produtos), 200

@app.route('/api/produtos/<int:produto_id>', methods=['DELETE'])
def delete_produto_route(produto_id):
    if 'usuario_id' not in session:
        return jsonify({"error": "Não autorizado"}), 401
    
    excluir_produto(produto_id, session['usuario_id'])
    return jsonify({"message": "Produto removido com sucesso"}), 200

@app.route('/api/enviar-lista', methods=['POST'])
def enviar_lista():
    if 'usuario_id' not in session:
        return jsonify({"error": "Não autorizado"}), 401
    
    data_envio = enviar_lista_produtos(session['usuario_id'])
    return jsonify({"message": "Lista enviada com sucesso", "data_envio": data_envio}), 200

@app.route('/api/validar-lista', methods=['POST'])
def validar_lista_route():
    if 'usuario_id' not in session or not session.get('admin'):
        return jsonify({"error": "Não autorizado"}), 401
    
    data = request.json
    data_envio = data.get('data_envio')
    nome_usuario = data.get('nome_usuario')
    
    if not data_envio or not nome_usuario:
        return jsonify({"error": "Dados incompletos"}), 400
    
    if validar_lista(data_envio, nome_usuario, session['usuario_id']):
        return jsonify({"message": "Lista validada com sucesso", "validador": session['usuario_nome']}), 200
    else:
        return jsonify({"error": "Erro ao validar lista"}), 500

@app.route('/api/export', methods=['GET'])
def export_excel():
    if 'usuario_id' not in session:
        return jsonify({"error": "Não autorizado"}), 401
    
    produtos = carregar_produtos_usuario(session['usuario_id'], apenas_nao_enviados=True)
    
    if not produtos:
        return jsonify({"error": "Não há produtos para exportar"}), 400
    
    # Criar DataFrame com os dados
    df = pd.DataFrame(produtos)
    
    # Selecionar e renomear colunas conforme solicitado pelo usuário
    df_export = df[['ean', 'nome', 'quantidade']].copy()
    df_export.columns = ['EAN', 'DESCRIÇÃO', 'QUANTIDADE']
    
    # Criar buffer para o arquivo Excel
    output = io.BytesIO()
    
    # Criar arquivo Excel
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df_export.to_excel(writer, index=False, sheet_name='Produtos')
    
    output.seek(0)
    
    # Gerar nome do arquivo com timestamp
    filename = f"produtos_ean_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    
    return send_file(
        output, 
        as_attachment=True,
        download_name=filename,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

if __name__ == '__main__':
    # Porta padrão para o Render é definida pela variável de ambiente PORT
    port = int(os.environ.get('PORT', 5010))
    app.run(host='0.0.0.0', port=port)
