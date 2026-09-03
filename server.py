"""
server.py

Servidor web do NetGuard (FastAPI).

Por enquanto expõe só a rota de login. Nos próximos passos, as rotas
de scan/devices/reports/sniffer vão ser adicionadas aqui, chamando o
ScannerEngine/SnifferModule já existentes.

Para rodar:
    uvicorn server:app --reload
"""

from datetime import timedelta

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Session, select

from database import get_session, create_db_and_tables
from db_models import User
from auth import verify_password, create_access_token, decode_access_token

app = FastAPI(title="NetGuard Cyber Defense Web Engine")

# Aponta para a rota de login; usado pelo Swagger (/docs) e para
# extrair o token do header "Authorization: Bearer <token>".
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@app.on_event("startup")
def on_startup():
    """Garante que o banco e as tabelas existem ao subir o servidor."""
    create_db_and_tables()


# ---------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------

@app.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
):
    """
    Autentica usuário/senha e retorna um token JWT.
    Compatível com o padrão OAuth2 (form-urlencoded: username, password),
    o que permite testar direto pela tela do Swagger em /docs.
    """
    user = session.exec(select(User).where(User.username == form_data.username)).first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(username=user.username, role=user.role)
    return {"access_token": token, "token_type": "bearer"}


# ---------------------------------------------------------------------
# Dependência de autenticação (para proteger rotas futuras)
# ---------------------------------------------------------------------

def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
) -> User:
    """
    Valida o token JWT enviado no header Authorization e retorna o
    usuário correspondente. Use como Depends() em qualquer rota que
    deva exigir login.
    """
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = payload.get("sub")
    user = session.exec(select(User).where(User.username == username)).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário do token não encontrado",
        )
    return user


# ---------------------------------------------------------------------
# Rota de teste, só para validar que a autenticação está funcionando
# ---------------------------------------------------------------------

@app.get("/me")
def read_current_user(current_user: User = Depends(get_current_user)):
    """Retorna os dados do usuário logado. Serve só para testar o token."""
    return {
        "username": current_user.username,
        "role": current_user.role,
        "created_at": current_user.created_at,
    }
