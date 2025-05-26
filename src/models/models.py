"""
Modelos SQLAlchemy para o sistema EAN.
Define as tabelas e relacionamentos do banco de dados.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# Importar a instância do SQLAlchemy
from db_config import db

class Usuario(db.Model, UserMixin):
    """
    Modelo para a tabela de usuários.
    """
    __tablename__ = 'usuarios'
    
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80), unique=True, nullable=False)
    senha_hash = db.Column(db.String(255), nullable=False)
    admin = db.Column(db.Integer, default=0)
    
    # Relacionamentos
    produtos = db.relationship('Produto', backref='usuario', lazy=True, foreign_keys='Produto.usuario_id')
    produtos_validados = db.relationship('Produto', backref='validador', lazy=True, foreign_keys='Produto.validador_id')
    
    def __init__(self, nome, senha, admin=0):
        self.nome = nome
        self.senha_hash = generate_password_hash(senha)
        self.admin = admin
    
    def verificar_senha(self, senha):
        return check_password_hash(self.senha_hash, senha)
    
    def to_dict(self):
        return {
            'id': self.id,
            'nome': self.nome,
            'admin': self.admin
        }

class Produto(db.Model):
    """
    Modelo para a tabela de produtos.
    """
    __tablename__ = 'produtos'
    
    id = db.Column(db.Integer, primary_key=True)
    ean = db.Column(db.String(20), nullable=False)
    nome = db.Column(db.String(255), nullable=False)
    cor = db.Column(db.String(50))
    voltagem = db.Column(db.String(20))
    modelo = db.Column(db.String(100))
    quantidade = db.Column(db.Integer, nullable=False, default=1)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    timestamp = db.Column(db.String(30))
    enviado = db.Column(db.Integer, default=0)
    data_envio = db.Column(db.String(30))
    validado = db.Column(db.Integer, default=0)
    validador_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'))
    data_validacao = db.Column(db.String(30))
    
    def __init__(self, ean, nome, usuario_id, quantidade=1, cor=None, voltagem=None, modelo=None):
        self.ean = ean
        self.nome = nome
        self.cor = cor
        self.voltagem = voltagem
        self.modelo = modelo
        self.quantidade = quantidade
        self.usuario_id = usuario_id
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.enviado = 0
    
    def to_dict(self):
        return {
            'id': self.id,
            'ean': self.ean,
            'nome': self.nome,
            'cor': self.cor,
            'voltagem': self.voltagem,
            'modelo': self.modelo,
            'quantidade': self.quantidade,
            'usuario_id': self.usuario_id,
            'timestamp': self.timestamp,
            'enviado': self.enviado,
            'data_envio': self.data_envio,
            'validado': self.validado,
            'validador_id': self.validador_id,
            'data_validacao': self.data_validacao
        }

def init_database(app):
    """
    Inicializa o banco de dados com as tabelas e dados iniciais.
    """
    with app.app_context():
        # Criar todas as tabelas
        db.create_all()
        
        # Verificar se já existe um admin
        admin = Usuario.query.filter_by(admin=1).first()
        
        if not admin:
            # Criar usuários administradores padrão
            admin_users = [
                {"nome": "admin", "senha": "admin", "admin": 1},
                {"nome": "Alessandro", "senha": "123456", "admin": 1},
                {"nome": "Celso", "senha": "123456", "admin": 1},
                {"nome": "Robson", "senha": "123456", "admin": 1},
                {"nome": "Teste1", "senha": "123456", "admin": 0}
            ]
            
            for user_data in admin_users:
                try:
                    user = Usuario(
                        nome=user_data["nome"],
                        senha=user_data["senha"],
                        admin=user_data["admin"]
                    )
                    db.session.add(user)
                    print(f"Usuário {'administrador' if user_data['admin'] == 1 else 'padrão'} '{user_data['nome']}' criado.")
                except Exception as e:
                    print(f"Erro ao criar usuário {user_data['nome']}: {str(e)}")
                    db.session.rollback()
            
            db.session.commit()
