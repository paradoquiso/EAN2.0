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

# Mapeamento de responsáveis autorizados
RESPONSAVEIS_AUTORIZADOS = ["Liliane", "Rogerio", "Celso", "Marcos"]

# Mapeamento seguro de senhas PI para responsáveis (hash:responsável)
# Este dicionário será usado apenas para verificação, não para armazenamento
SENHAS_PI_HASH = {
    generate_password_hash("5584"): "Liliane",
    generate_password_hash("9841"): "Rogerio",
    generate_password_hash("2122"): "Celso",
    generate_password_hash("6231"): "Marcos"
}

# Funções auxiliares
def validar_senha_pi(senha_pi, responsavel_informado):
    """
    Valida a senha PI e verifica se corresponde ao responsável informado.
    
    Args:
        senha_pi (str): Senha PI de 4 dígitos
        responsavel_informado (str): Nome do responsável informado pelo usuário
        
    Returns:
        dict: Dicionário com status de sucesso e nome do responsável (se válido)
    """
    # Validar formato da senha (4 dígitos)
    if not senha_pi or not senha_pi.isdigit() or len(senha_pi) != 4:
        return {
            "success": False,
            "message": "Senha PI inválida. Deve conter 4 dígitos numéricos."
        }
    
    # Validar se o responsável foi informado e é válido
    if not responsavel_informado or responsavel_informado not in RESPONSAVEIS_AUTORIZADOS:
        return {
            "success": False,
            "message": "Responsável inválido ou não informado."
        }
    
    # Verificar a senha usando comparação segura
    for senha_hash, responsavel in SENHAS_PI_HASH.items():
        if check_password_hash(senha_hash, senha_pi) and responsavel == responsavel_informado:
            return {
                "success": True,
                "responsavel": responsavel,
                "message": f"Senha PI validada com sucesso. Responsável: {responsavel}"
            }
    
    return {
        "success": False,
        "message": "Senha PI não reconhecida ou não corresponde ao responsável informado. Por favor, verifique e tente novamente."
    }

def buscar_produto_local(ean, usuario_id):
    produto = Produto.query.filter_by(ean=ean, usuario_id=usuario_id).first()
    if produto:
        return produto.to_dict()
    return None

def buscar_produto_online(ean):
    # Função existente mantida sem alterações
    # ...
    pass

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
        produto_dict = produto.to_dict()  # Já não inclui senha_pi
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
        produto_dict = produto.to_dict()  # Já não inclui senha_pi
        produto_dict['nome_usuario'] = nome_usuario
        produto_dict['nome_validador'] = nome_validador
        resultado.append(produto_dict)
    
    return resultado

def enviar_lista_produtos(usuario_id, senha_pi, responsavel_informado):
    """
    Envia a lista de produtos para o painel administrativo, com autenticação por senha PI.
    
    Args:
        usuario_id (int): ID do usuário que está enviando a lista
        senha_pi (str): Senha PI de 4 dígitos para autenticação
        responsavel_informado (str): Nome do responsável informado pelo usuário
        
    Returns:
        dict: Dicionário com status de sucesso e mensagem
    """
    # Validar a senha PI e o responsável
    validacao = validar_senha_pi(senha_pi, responsavel_informado)
    if not validacao["success"]:
        return validacao
    
    responsavel_pi = validacao["responsavel"]
    data_envio = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data_autorizacao = data_envio  # Mesma data/hora para autorizacao
    
    # Gerar hash da senha PI para armazenamento seguro
    senha_pi_hash = generate_password_hash(senha_pi)
    
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
        produto.senha_pi_hash = senha_pi_hash  # Armazenar hash em vez de texto puro
        produto.data_autorizacao = data_autorizacao
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
    
    try:
        db.session.commit()
        return True
    except:
        db.session.rollback()
        return False

# Resto do código mantido sem alterações
# ...
