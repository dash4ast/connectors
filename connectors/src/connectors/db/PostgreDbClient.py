import sqlalchemy
from sqlalchemy.orm import sessionmaker, scoped_session
import os

host_db = os.environ['DASH4AST_DB_HOST']
port_db = os.environ['DASH4AST_DB_PORT']
username_db = os.environ['DASH4AST_DB_USER']
password_db = os.environ['DASH4AST_DB_PASSWORD']
schema = os.environ['DASH4AST_DB']


class PostgreDbClient:
    def __init__(self):
        self.host = host_db
        self.port = port_db
        self.username = username_db
        self.password = password_db
        self.schema = schema
        self.url = f'postgresql://{self.username}:{self.password}@{self.host}:{self.port}'

        schema_url = self.url + '/' + self.schema
        engine = sqlalchemy.create_engine(schema_url, pool_pre_ping=True)
        session_factory = sessionmaker(bind=engine)
        self.postgredb_session = scoped_session(session_factory)

    def get_client(self):
        return self.postgredb_session
