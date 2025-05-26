from src.database import db
from datetime import datetime

class Usuario(db.Model):
    __tablename__ = 'usuarios'
    
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)
    senha_hash = db.Column(db.String(200), nullable=False)
    admin = db.Column(db.Integer, default=0)
    
    # Relacionamento com produtos
    produtos = db.relationship('Produto', backref='usuario', lazy=True, 
                              foreign_keys='Produto.usuario_id')
    
    # Relacionamento com produtos validados
    produtos_validados = db.relationship('Produto', backref='validador', lazy=True,
                                        foreign_keys='Produto.validador_id')
    
    def __repr__(self):
        return f'<Usuario {self.nome}>'
