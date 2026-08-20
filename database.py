from sqlmodel import SQLModel, create_engine, Session

import db_models  # noqa: F401

DATABASE_URL = "sqlite:///netguard.db"

engine = create_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})


def create_db_and_tables() -> None:
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session


if __name__ == "__main__":
    create_db_and_tables()
    print("Banco de dados 'netguard.db' criado/verificado com sucesso.")
