from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

# Classes mapped using the declarative system are defined in terms of a base
# class which maintains a catalog of classes and tables relative to that base -
# this is known as the declarative base class.
# declarative_base() is a factory function that constructs a base class for
# declarative class definitions (assigned to Base variable in this example).
Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    """ Table for user information.

    Columns:
        id: Distinct user id.
        name: Name of the user.
        email: E-Mail of the user.
        picture: Path to external profile picture.
    """

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Collection(Base):
    __tablename__ = 'collection'
    """ Table for music collections.

    Columns:
        id: Distinct collection id.
        name: Name of the collection.
        user_id: user who created the collection.
    """

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    # Decorator method
    @property
    def serialize(self):
        """ Selects and formats collection data.

        This serializable function will help define what data should be
        send across and put it in a format that Flask can easily use.
        """
        # Returns object data in easily serializeable format
        return {
            'id': self.id,
            'name': self.name
        }


class Album(Base):
    __tablename__ = 'album'
    """ Table for music album information.

    Columns:
        id: Distinct album id.
        name: Album title.
        artist: Album artist.
        genre: Album genre.
        year: Year in which the album got published.
        description: Additional album information.
        cover_source: Source of the optional album cover image.
        cover_image: filename or external path to the optional album cover image.
        user_id: user who created the album.
        collection_id: collections where the album belongs to.
    """

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    artist = Column(String(250), nullable=False)
    genre = Column(String(100), nullable=False)
    year = Column(String(4))
    description = Column(String(250))
    cover_source = Column(String(5))
    cover_image = Column(String(250))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    collection_id = Column(Integer, ForeignKey('collection.id'))
    collection = relationship(Collection)

    # Decorator method
    @property
    def serialize(self):
        """ Selects and formats album data.

        This serializable function will help define what data should be
        send across and put it in a format that Flask can easily use.
        """

        # Returns object data in easily serializable format
        return {
            'id': self.id,
            'name': self.name,
            'artist': self.artist,
            'genre': self.artist,
            'year': self.year,
            'description': self.description
        }


engine = create_engine('sqlite:///musiccollections.db')
# Initialize database schema (create tables).
Base.metadata.create_all(engine)
