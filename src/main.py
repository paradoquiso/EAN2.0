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

# Mapeamento de senhas PI para responsáveis
SENHAS_PI = {
    "5584": "Liliane",
    "9841": "Rogerio",
    "2122": "Celso",
    "6231": "Marcos"
}

# Funções auxiliares
def validar_senha_pi(senha_pi):
    """
    Valida a senha PI e retorna o nome do responsável associado.
    
    Args:
        senha_pi (str): Senha PI de 4 dígitos
        
    Returns:
        dict: Dicionário com status de sucesso e nome do responsável (se válido)
    """
    # Validar formato da senha (4 dígitos)
    if not senha_pi or not senha_pi.isdigit() or len(senha_pi) != 4:
        return {
            "success": False,
            "message": "Senha PI inválida. Deve conter 4 dígitos numéricos."
        }
    
    # Verificar se a senha existe no mapeamento
    if senha_pi in SENHAS_PI:
        return {
            "success": True,
            "responsavel": SENHAS_PI[senha_pi],
            "message": f"Senha PI validada com sucesso. Responsável: {SENHAS_PI[senha_pi]}"
        }
    else:
        return {
            "success": False,
            "message": "Senha PI não reconhecida. Por favor, verifique e tente novamente."
        }

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

def enviar_lista_produtos(usuario_id, senha_pi):
    """
    Envia a lista de produtos para o painel administrativo, com autenticação por senha PI.
    
    Args:
        usuario_id (int): ID do usuário que está enviando a lista
        senha_pi (str): Senha PI de 4 dígitos para autenticação
        
    Returns:
        dict: Dicionário com status de sucesso e mensagem
    """
    # Validar a senha PI
    validacao = validar_senha_pi(senha_pi)
    if not validacao["success"]:
        return validacao
    
    responsavel_pi = validacao["responsavel"]
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
        return {
            "success": False,
            "message": "Nenhum produto encontrado para enviar."
        }
    
    for produto in produtos:
        produto.enviado = 1  # Usar 1 em vez de true
        produto.data_envio = data_envio
        produto.responsavel_pi = responsavel_pi
        produto.senha_pi = senha_pi
        logger.info(f"Produto {produto.id} ({produto.nome}) marcado como enviado, responsável PI: {responsavel_pi}")
    
    try:
        db.session.commit()
        logger.info(f"Commit realizado com sucesso, {len(produtos)} produtos enviados com responsável PI: {responsavel_pi}")
        
        # Verificar se os produtos foram realmente atualizados
        produtos_verificacao = Produto.query.filter_by(
            usuario_id=usuario_id,
            enviado=1,
            data_envio=data_envio,
            responsavel_pi=responsavel_pi
        ).all()
        
        logger.info(f"Verificação pós-commit: {len(produtos_verificacao)} produtos encontrados com data_envio={data_envio}")
        
        return {
            "success": True,
            "data_envio": data_envio,
            "responsavel_pi": responsavel_pi,
            "message": f"Lista enviada com sucesso! Responsável: {responsavel_pi}"
        }
    except Exception as e:
        logger.error(f"Erro ao fazer commit das alterações: {str(e)}")
        db.session.rollback()
        return {
            "success": False,
            "message": f"Erro ao enviar lista: {str(e)}"
        }

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
        chave = (produto['nome_usuario'], produto['data_envio'], produto.get('responsavel_pi', ''))
        if chave not in listas_por_usuario:
            listas_por_usuario[chave] = []
        listas_por_usuario[chave].append(produto)
    
    # Log para depuração
    logger.info(f"Rota /admin: Agrupados em {len(listas_por_usuario)} listas distintas")
    for (nome_usuario, data_envio, responsavel_pi), produtos in listas_por_usuario.items():
        logger.info(f"Lista de {nome_usuario} enviada em {data_envio} por {responsavel_pi} contém {len(produtos)} produtos")
    
    return render_template('admin.html', nome_usuario=nome_usuario, listas_por_usuario=listas_por_usuario)

# API Routes
@app.route('/api/buscar-produto', methods=['GET'])
def api_buscar_produto():
    if 'usuario_id' not in session:
        return jsonify({'success': False, 'message': 'Usuário não autenticado'})
    
    ean = request.args.get('ean', '')
    if not ean:
        return jsonify({'success': False, 'message': 'EAN não fornecido'})
    
    usuario_id = session['usuario_id']
    
    # Verificar se o produto já existe localmente
    produto_local = buscar_produto_local(ean, usuario_id)
    if produto_local:
        return jsonify({
            'success': True,
            'nome': produto_local['nome'],
            'cor': produto_local['cor'],
            'voltagem': produto_local['voltagem'],
            'modelo': produto_local['modelo'],
            'quantidade': produto_local['quantidade'],
            'message': 'Produto encontrado localmente'
        })
    
    # Buscar produto online
    resultado = buscar_produto_online(ean)
    return jsonify(resultado)

@app.route('/api/produtos', methods=['GET', 'POST'])
def api_produtos():
    if 'usuario_id' not in session:
        return jsonify({'success': False, 'message': 'Usuário não autenticado'})
    
    usuario_id = session['usuario_id']
    
    if request.method == 'POST':
        data = request.get_json()
        
        ean = data.get('ean', '')
        nome = data.get('nome', '')
        cor = data.get('cor', '')
        voltagem = data.get('voltagem', '')
        modelo = data.get('modelo', '')
        quantidade = data.get('quantidade', 1)
        
        if not ean or not nome:
            return jsonify({'success': False, 'message': 'EAN e nome são obrigatórios'})
        
        # Verificar se o produto já existe
        produto_existente = Produto.query.filter_by(ean=ean, usuario_id=usuario_id, enviado=0).first()
        if produto_existente:
            produto_existente.nome = nome
            produto_existente.cor = cor
            produto_existente.voltagem = voltagem
            produto_existente.modelo = modelo
            produto_existente.quantidade = quantidade
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Produto atualizado com sucesso',
                'produtos': carregar_produtos_usuario(usuario_id)
            })
        
        # Criar novo produto
        novo_produto = Produto(
            ean=ean,
            nome=nome,
            cor=cor,
            voltagem=voltagem,
            modelo=modelo,
            quantidade=quantidade,
            usuario_id=usuario_id
        )
        
        db.session.add(novo_produto)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Produto adicionado com sucesso',
            'produtos': carregar_produtos_usuario(usuario_id)
        })
    
    # GET request - retornar todos os produtos do usuário
    produtos = carregar_produtos_usuario(usuario_id)
    return jsonify({'success': True, 'produtos': produtos})

@app.route('/api/produtos/<int:produto_id>', methods=['DELETE'])
def api_deletar_produto(produto_id):
    if 'usuario_id' not in session:
        return jsonify({'success': False, 'message': 'Usuário não autenticado'})
    
    usuario_id = session['usuario_id']
    
    produto = Produto.query.filter_by(id=produto_id, usuario_id=usuario_id).first()
    if not produto:
        return jsonify({'success': False, 'message': 'Produto não encontrado'})
    
    db.session.delete(produto)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Produto removido com sucesso',
        'produtos': carregar_produtos_usuario(usuario_id)
    })

@app.route('/api/enviar-lista', methods=['POST'])
def api_enviar_lista():
    if 'usuario_id' not in session:
        return jsonify({'success': False, 'message': 'Usuário não autenticado'})
    
    usuario_id = session['usuario_id']
    
    # Obter a senha PI do corpo da requisição
    data = request.get_json()
    senha_pi = data.get('senha_pi', '')
    
    if not senha_pi:
        return jsonify({
            'success': False,
            'message': 'Senha PI não fornecida. Por favor, informe a senha PI para confirmar o envio.'
        })
    
    # Enviar a lista com autenticação PI
    logger.info(f"Iniciando envio de lista para o usuário {usuario_id} com senha PI {senha_pi}")
    resultado = enviar_lista_produtos(usuario_id, senha_pi)
    
    if resultado["success"]:
        logger.info(f"Lista enviada com sucesso, data_envio: {resultado['data_envio']}, responsável: {resultado['responsavel_pi']}")
    else:
        logger.error(f"Erro ao enviar lista: {resultado['message']}")
    
    return jsonify(resultado)

@app.route('/api/validar-lista', methods=['POST'])
def api_validar_lista():
    if 'usuario_id' not in session or not session.get('admin'):
        return jsonify({'success': False, 'message': 'Acesso não autorizado'})
    
    validador_id = session['usuario_id']
    data = request.get_json()
    
    nome_usuario = data.get('nome_usuario', '')
    data_envio = data.get('data_envio', '')
    
    if not nome_usuario or not data_envio:
        return jsonify({'success': False, 'message': 'Parâmetros inválidos'})
    
    resultado = validar_lista(data_envio, nome_usuario, validador_id)
    
    if resultado:
        return jsonify({'success': True, 'message': 'Lista validada com sucesso'})
    else:
        return jsonify({'success': False, 'message': 'Erro ao validar lista'})

@app.route('/api/exportar-excel', methods=['POST'])
def api_exportar_excel():
    if 'usuario_id' not in session or not session.get('admin'):
        return jsonify({'success': False, 'message': 'Acesso não autorizado'})
    
    data = request.get_json()
    nome_usuario = data.get('nome_usuario', '')
    data_envio = data.get('data_envio', '')
    
    if not nome_usuario or not data_envio:
        return jsonify({'success': False, 'message': 'Parâmetros inválidos'})
    
    # Obter o ID do usuário pelo nome
    usuario = Usuario.query.filter_by(nome=nome_usuario).first()
    if not usuario:
        return jsonify({'success': False, 'message': 'Usuário não encontrado'})
    
    usuario_id = usuario.id
    
    # Buscar produtos da lista
    produtos = Produto.query.filter_by(
        usuario_id=usuario_id,
        data_envio=data_envio,
        enviado=1  # Usar 1 em vez de true
    ).all()
    
    if not produtos:
        return jsonify({'success': False, 'message': 'Nenhum produto encontrado'})
    
    # Criar DataFrame
    dados = []
    for produto in produtos:
        dados.append({
            'EAN': produto.ean,
            'Nome': produto.nome,
            'Cor': produto.cor,
            'Voltagem': produto.voltagem,
            'Modelo': produto.modelo,
            'Quantidade': produto.quantidade,
            'Data de Envio': produto.data_envio,
            'Responsável PI': produto.responsavel_pi
        })
    
    df = pd.DataFrame(dados)
    
    # Criar arquivo Excel em memória
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Produtos')
    
    output.seek(0)
    
    # Gerar nome do arquivo
    nome_arquivo = f"lista_{nome_usuario}_{data_envio.replace(' ', '_').replace(':', '-')}.xlsx"
    
    # Salvar temporariamente o arquivo
    caminho_arquivo = os.path.join(app.root_path, 'temp', nome_arquivo)
    os.makedirs(os.path.dirname(caminho_arquivo), exist_ok=True)
    
    with open(caminho_arquivo, 'wb') as f:
        f.write(output.getvalue())
    
    return jsonify({
        'success': True,
        'message': 'Excel gerado com sucesso',
        'arquivo': nome_arquivo
    })

@app.route('/download-excel/<nome_arquivo>')
def download_excel(nome_arquivo):
    if 'usuario_id' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    
    caminho_arquivo = os.path.join(app.root_path, 'temp', nome_arquivo)
    
    if not os.path.exists(caminho_arquivo):
        return "Arquivo não encontrado", 404
    
    return send_file(caminho_arquivo, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
