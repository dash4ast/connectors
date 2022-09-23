from sqlalchemy.ext.declarative import declarative_base


class Base:
    """
    Augmentation class of sql alchemy Base object
    All ORM objects to be mapped with the database must implement 'Base'.
    Exposes a method to convert the mapped table registry in to a dictionary (to_dict)
    """
    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


Base = declarative_base(cls=Base)