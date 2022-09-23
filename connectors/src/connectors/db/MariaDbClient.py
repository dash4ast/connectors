import sqlalchemy
from sqlalchemy.orm import sessionmaker, scoped_session
import os

host_db = os.environ['host_db']
port_db = os.environ['port_db']
username_db = 'root'
password_db = os.environ['password_root']
schema = os.environ['schema_db']


class MariaDbClient:
    def __init__(self):
        self.host = host_db
        self.port = port_db
        self.username = username_db
        self.password = password_db
        self.schema = schema
        self.url = f'mysql+pymysql://{self.username}:{self.password}@{self.host}:{self.port}'

        schema_url = self.url + '/' + self.schema
        engine = sqlalchemy.create_engine(schema_url, pool_pre_ping=True)
        session_factory = sessionmaker(bind=engine)
        self.mariadb_session = scoped_session(session_factory)

    def get_client(self):
        return self.mariadb_session
