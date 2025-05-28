import os
import sys
from werkzeug.security import generate_password_hash
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Adicionar o diretório pai ao path para importar os módulos
sys.path.append('/home/ubuntu')

# Script para adicionar um usuário admin diretamente no banco de dados PostgreSQL
# Útil quando o processo automático de criação falha

# Configuração da conexão com o banco de dados
DATABASE_URL = "postgresql://data_base_ean_user:8iqHYjWBXBeCVEOxCVUcEcfOoLmbQWA4@dpg-d0qbpsh5pdvs73afm3ag-a.oregon-postgres.render.com/data_base_ean"

def criar_admin_manual():
    """Cria um usuário admin diretamente no banco de dados"""
    try:
        # Criar engine de conexão com o banco
        engine = create_engine(DATABASE_URL)
        
        # Criar sessão
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Verificar se a tabela usuarios existe
        result = session.execute(text("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'usuarios')"))
        tabela_existe = result.scalar()
        
        if not tabela_existe:
            print("A tabela 'usuarios' não existe. Criando tabela...")
            session.execute(text("""
                CREATE TABLE IF NOT EXISTS usuarios (
                    id SERIAL PRIMARY KEY,
                    nome VARCHAR(100) UNIQUE NOT NULL,
                    senha_hash VARCHAR(200) NOT NULL,
                    admin INTEGER DEFAULT 0
                )
            """))
            session.commit()
            print("Tabela 'usuarios' criada com sucesso.")
        
        # Verificar se já existe um admin
        result = session.execute(text("SELECT COUNT(*) FROM usuarios WHERE admin = 1"))
        admin_existe = result.scalar() > 0
        
        if admin_existe:
            print("Usuário admin já existe. Atualizando senha...")
            # Atualizar senha do admin existente
            senha_hash = generate_password_hash('admin')
            session.execute(
                text("UPDATE usuarios SET senha_hash = :senha_hash WHERE admin = 1"),
                {"senha_hash": senha_hash}
            )
        else:
            print("Criando novo usuário admin...")
            # Criar um novo usuário admin
            senha_hash = generate_password_hash('admin')
            session.execute(
                text("INSERT INTO usuarios (nome, senha_hash, admin) VALUES (:nome, :senha_hash, :admin)"),
                {"nome": "admin", "senha_hash": senha_hash, "admin": 1}
            )
        
        session.commit()
        print("Usuário admin criado/atualizado com sucesso!")
        return True
    
    except Exception as e:
        print(f"Erro ao criar usuário admin: {str(e)}")
        return False

if __name__ == "__main__":
    criar_admin_manual()
