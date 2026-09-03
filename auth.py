"""
auth.py

Funções de segurança do NetGuard Web Engine: hash/verificação de senha
(bcrypt) e criação/validação de tokens JWT de sessão.

"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from jose import JWTError, jwt

# ---------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------

# Em produção, defina a variável de ambiente NETGUARD_SECRET_KEY.
# Se não definida, gera uma chave só para esta execução (bom para
# testar localmente, mas invalida tokens antigos a cada reinício).
SECRET_KEY = os.getenv("NETGUARD_SECRET_KEY", os.urandom(32).hex())
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ---------------------------------------------------------------------
# Senhas
# ---------------------------------------------------------------------
# Bcrypt trunca a senha em 72 bytes por limitação do próprio algoritmo;

def hash_password(plain_password: str) -> str:
    """Gera o hash bcrypt de uma senha em texto puro."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Confere se a senha em texto puro corresponde ao hash salvo."""
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


# ---------------------------------------------------------------------
# Tokens JWT
# ---------------------------------------------------------------------

def create_access_token(username: str, role: str = "user") -> str:
    """
    Cria um token JWT de sessão para o usuário autenticado.
    O payload carrega o username ("sub") e o role, com expiração.
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "role": role, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    """
    Valida e decodifica um token JWT.
    Retorna o payload se for válido, ou None se for inválido/expirado.
    """
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


# ---------------------------------------------------------------------
# Utilitário: criar o primeiro usuário admin
# ---------------------------------------------------------------------

def create_user(username: str, plain_password: str, role: str = "admin") -> None:
    """
    Cria um usuário no banco. Útil para gerar o primeiro admin,
    já que ainda não existe uma rota web de cadastro.
    Uso: python auth.py criar_admin
    """
    from sqlmodel import Session, select
    from database import engine
    from db_models import User

    with Session(engine) as session:
        existing = session.exec(select(User).where(User.username == username)).first()
        if existing:
            print(f"Usuário '{username}' já existe.")
            return

        user = User(
            username=username,
            hashed_password=hash_password(plain_password),
            role=role,
        )
        session.add(user)
        session.commit()
        print(f"Usuário '{username}' ({role}) criado com sucesso.")


if __name__ == "__main__":
    import sys
    from database import create_db_and_tables

    create_db_and_tables()

    if len(sys.argv) == 2 and sys.argv[1] == "criar_admin":
        username = input("Nome de usuário do admin: ").strip()
        password = input("Senha do admin: ").strip()
        create_user(username, password, role="admin")
    else:
        print("Uso: python auth.py criar_admin")
