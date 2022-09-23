from sqlalchemy import Column, String, DateTime

from connectors.persistence.Base import Base


class Application(Base):
    __tablename__ = 'applications'

    application_name = Column(String(255), primary_key=True)
    domain_name = Column(String(255))
    description = Column(String(512))
    threshold = Column(String(255))
    business_risk = Column(String(255))
