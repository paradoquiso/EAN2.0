import os
from dotenv import load_dotenv

# Carregar variáveis de ambiente do arquivo .env, se existir
load_dotenv()

class Config:
    """Configuração base"""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'ean_app_secret_key')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Definir a URL do banco de dados diretamente na classe base
    # para garantir que sempre esteja disponível
    DATABASE_URL = "postgresql://data_base_ean_user:8iqHYjWBXBeCVEOxCVUcEcfOoLmbQWA4@dpg-d0qbpsh5pdvs73afm3ag-a.oregon-postgres.render.com/data_base_ean"
    
    # Usar variável de ambiente se disponível, caso contrário usar a URL hardcoded
    database_url = os.environ.get('DATABASE_URL', DATABASE_URL)
    
    # Ajustar URL para formato compatível com SQLAlchemy se necessário
    if database_url and database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    
    # Definir SQLALCHEMY_DATABASE_URI na classe base
    SQLALCHEMY_DATABASE_URI = database_url
    
class DevelopmentConfig(Config):
    """Configuração de desenvolvimento"""
    DEBUG = True
    # Se quiser usar SQLite em desenvolvimento, descomente a linha abaixo
    # SQLALCHEMY_DATABASE_URI = 'sqlite:///../produtos.db'
    
class ProductionConfig(Config):
    """Configuração de produção"""
    DEBUG = False
    
# Selecionar configuração com base no ambiente
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': ProductionConfig  # Alterado para ProductionConfig como padrão
}

def get_config():
    """Retorna a configuração com base no ambiente"""
    env = os.environ.get('FLASK_ENV', 'production')  # Alterado para production como padrão
    return config.get(env, config['default'])
