from src.database import db
from datetime import datetime

class Produto(db.Model):
    __tablename__ = 'produtos'
    
    id = db.Column(db.Integer, primary_key=True)
    ean = db.Column(db.String(50), nullable=False)
    nome = db.Column(db.String(255), nullable=False)
    cor = db.Column(db.String(100))
    voltagem = db.Column(db.String(100))
    modelo = db.Column(db.String(100))
    quantidade = db.Column(db.Integer, default=1)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    timestamp = db.Column(db.String(50), default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    # Campos para controle de envio
    enviado = db.Column(db.Integer, default=0)  # 0 = não enviado, 1 = enviado
    data_envio = db.Column(db.String(50))
    
    # Campos para autenticação PI
    responsavel_pi = db.Column(db.String(100))  # Nome do responsável pela senha PI
    senha_pi = db.Column(db.String(10))  # Senha PI utilizada (para auditoria)
    
    # Campos para validação administrativa
    validado = db.Column(db.Integer, default=0)  # 0 = não validado, 1 = validado
    validador_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'))
    data_validacao = db.Column(db.String(50))
    
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
            'responsavel_pi': self.responsavel_pi,
            'senha_pi': self.senha_pi,
            'validado': self.validado,
            'validador_id': self.validador_id,
            'data_validacao': self.data_validacao
        }
