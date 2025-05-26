import os
from dotenv import load_dotenv

# Carregar variáveis de ambiente do arquivo .env, se existir
load_dotenv()

class Config:
    """Configuração base"""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'ean_app_secret_key')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
class DevelopmentConfig(Config):
    """Configuração de desenvolvimento"""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///../produtos.db')
    
class ProductionConfig(Config):
    """Configuração de produção"""
    DEBUG = False
    
    # Usar diretamente a URL do PostgreSQL fornecida
    DATABASE_URL = "postgresql://data_base_ean_user:8iqHYjWBXBeCVEOxCVUcEcfOoLmbQWA4@dpg-d0qbpsh5pdvs73afm3ag-a.oregon-postgres.render.com/data_base_ean"
    
    # Fallback para variável de ambiente se existir
    database_url = os.environ.get('DATABASE_URL', DATABASE_URL)
    
    # Ajustar URL para formato compatível com SQLAlchemy se necessário
    if database_url and database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    
    SQLALCHEMY_DATABASE_URI = database_url

# Selecionar configuração com base no ambiente
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Retorna a configuração com base no ambiente"""
    env = os.environ.get('FLASK_ENV', 'production')  # Alterado para production como padrão
    return config.get(env, config['default'])
