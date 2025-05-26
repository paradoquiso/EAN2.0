"""
Configuração do banco de dados para o sistema EAN.
Suporta PostgreSQL no ambiente de produção (Render) e SQLite em desenvolvimento.
"""

import os
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

# Inicialização do SQLAlchemy
db = SQLAlchemy()

def get_database_url():
    """
    Retorna a URL de conexão com o banco de dados apropriada para o ambiente.
    """
    # Verificar se estamos no ambiente de produção (Render)
    if os.environ.get('RENDER'):
        # Usar PostgreSQL em produção
        db_url = os.environ.get('DATABASE_URL')
        
        # Ajuste necessário para SQLAlchemy 1.4+
        if db_url and db_url.startswith('postgres://'):
            db_url = db_url.replace('postgres://', 'postgresql://', 1)
        
        return db_url or 'postgresql://ean_database_user:6UyjLr012czCc0Jk3H2TEaxV13MlV8cT@dpg-d0mrrf95pdvs739npajg-a/ean_database'
    else:
        # Usar SQLite em desenvolvimento
        sqlite_path = os.path.join(os.path.dirname(__file__), 'produtos.db')
        return f'sqlite:///{sqlite_path}'

def configure_db(app):
    """
    Configura o banco de dados para a aplicação Flask.
    """
    app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url()
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Inicializar o SQLAlchemy com a aplicação
    db.init_app(app)
    
    return db

def get_engine():
    """
    Retorna um engine SQLAlchemy para operações fora do contexto da aplicação.
    """
    return create_engine(get_database_url())

def get_session():
    """
    Retorna uma sessão SQLAlchemy para operações fora do contexto da aplicação.
    """
    engine = get_engine()
    session_factory = sessionmaker(bind=engine)
    return scoped_session(session_factory)
