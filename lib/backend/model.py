from sqlalchemy import ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import backref, foreign, relationship, remote
from sqlalchemy.sql.schema import Column
from sqlalchemy.types import Integer, String

Base = declarative_base()


class PasswordGroup(Base):
    __tablename__ = 'passwordgroup'
    id = Column(Integer, primary_key=True, autoincrement=True)
    group_id = Column(Integer, ForeignKey('group.id'), nullable=False)
    password_id = Column(Integer, ForeignKey('password.id'), nullable=False)


class Password(Base):
    __tablename__ = 'password'
    id = Column(Integer, primary_key=True, autoincrement=True)
    label = Column(String, nullable=False)
    login = Column(String, nullable=False)
    login_tag = Column(String, nullable=False)
    login_nonce = Column(String, nullable=False)
    password = Column(String, nullable=False)
    password_tag = Column(String, nullable=False)
    password_nonce = Column(String, nullable=False)
    notes = Column(String, nullable=True)
    notes_tag = Column(String, nullable=True)
    notes_nonce = Column(String, nullable=True)
    session_key = Column(String, nullable=False)

    family_key = Column(String, nullable=False)

    related_user_id = Column(Integer, ForeignKey('user.id'), nullable=False)

    user = relationship(
        'User', backref=backref('passwords', cascade='all, delete')
    )
    groups = relationship(
        'Group',
        secondary=PasswordGroup.__table__,
        backref=backref('passwords', cascade='all, delete'),
    )

    family = relationship(
        'Password',
        primaryjoin=remote(family_key) == foreign(family_key),
        uselist=True,
        viewonly=True,
    )


class UserGroup(Base):
    __tablename__ = 'usergroup'
    id = Column(Integer, primary_key=True, autoincrement=True)
    group_id = Column(Integer, ForeignKey('group.id'), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True, autoincrement=True)
    login = Column(String, nullable=False)
    password = Column(String, nullable=False)
    public_key = Column(String, nullable=False)
    private_key = Column(String, nullable=False)
    nonce = Column(String, nullable=False)

    groups = relationship(
        'Group', secondary=UserGroup.__table__, backref='users'
    )


class Group(Base):
    __tablename__ = 'group'
    id = Column(Integer, primary_key=True, autoincrement=True)
    label = Column(String, nullable=False)
