import sqlite3
import os
import sys
from werkzeug.security import generate_password_hash

# Caminho para o banco de dados SQLite
DB_FILE = 'produtos.db'

def adicionar_admin(nome, senha):
    """Adiciona um novo usuário administrador ou promove um usuário existente."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Verificar se o usuário já existe
    cursor.execute('SELECT id FROM usuarios WHERE nome = ?', (nome,))
    usuario = cursor.fetchone()
    
    if usuario:
        # Promover usuário existente a administrador
        cursor.execute('UPDATE usuarios SET admin = 1 WHERE nome = ?', (nome,))
        print(f"Usuário '{nome}' promovido a administrador com sucesso!")
    else:
        # Criar novo usuário administrador
        senha_hash = generate_password_hash(senha)
        cursor.execute('INSERT INTO usuarios (nome, senha_hash, admin) VALUES (?, ?, 1)', 
                      (nome, senha_hash))
        print(f"Novo administrador '{nome}' criado com sucesso!")
    
    conn.commit()
    conn.close()

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Uso: python adicionar_admin.py <nome> <senha>")
        sys.exit(1)
    
    nome = sys.argv[1]
    senha = sys.argv[2]
    
    adicionar_admin(nome, senha)
