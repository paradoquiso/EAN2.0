from src.database import db
from datetime import datetime

class Produto(db.Model):
    __tablename__ = 'produtos'
    
    id = db.Column(db.Integer, primary_key=True)
    ean = db.Column(db.String(20), nullable=False)
    nome = db.Column(db.String(200), nullable=False)
    cor = db.Column(db.String(50))
    voltagem = db.Column(db.String(20))
    modelo = db.Column(db.String(100))
    quantidade = db.Column(db.Integer, nullable=False)
    
    # Chaves estrangeiras
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    validador_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'))
    
    # Campos de controle
    timestamp = db.Column(db.String(20))
    enviado = db.Column(db.Integer, default=0)
    data_envio = db.Column(db.String(20))
    validado = db.Column(db.Integer, default=0)
    data_validacao = db.Column(db.String(20))
    
    # Novo campo para armazenar o responsável pela confirmação via PIN
    responsavel_pin = db.Column(db.String(50))
    
    def __repr__(self):
        return f'<Produto {self.ean}: {self.nome}>'
    
    def to_dict(self):
        """Converte o objeto para dicionário"""
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
            'data_validacao': self.data_validacao,
            'responsavel_pin': self.responsavel_pin
        }
