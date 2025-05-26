from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# Inicializar SQLAlchemy
db = SQLAlchemy()

# Base declarativa para modelos
Base = declarative_base()

def init_db(app):
    """Inicializa o banco de dados com a aplicação Flask"""
    db.init_app(app)
    
    with app.app_context():
        # Importar modelos para garantir que sejam registrados
        from src.models.usuario import Usuario
        from src.models.produto import Produto
        
        # Criar tabelas
        db.create_all()
        
        # Verificar se já existe um admin
        admin = Usuario.query.filter_by(admin=1).first()
        if not admin:
            # Criar um usuário admin padrão
            from werkzeug.security import generate_password_hash
            admin = Usuario(
                nome='admin',
                senha_hash=generate_password_hash('admin'),
                admin=1
            )
            db.session.add(admin)
            db.session.commit()
