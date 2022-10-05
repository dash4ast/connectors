from sqlalchemy import Column, String, DateTime, Integer

from connectors.persistence.Base import Base


class Analysis(Base):
    __tablename__ = 'analysis'

    analysis_id = Column(Integer, primary_key=True)
    analysis_date = Column(DateTime)
    application = Column(String(512))
    analysis_type = Column(String(255))
