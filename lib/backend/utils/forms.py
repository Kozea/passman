from flask import g, session
from wtforms import (
    Form, PasswordField, SelectField, SelectMultipleField, StringField)
from wtforms.validators import DataRequired, Optional, ValidationError
from wtforms.widgets import CheckboxInput, ListWidget

from ..model import Group, User


def mail_validator(form, field):
    if '@' not in field.data:
        raise ValidationError('Mail invalide')


class GroupForm(Form):
    label = StringField('Nom', [DataRequired()])


class PasswordForm(Form):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        group_ids = [
            group.id
            for group in g.session.query(User).get(session['user_id']).groups]
        groups = (
            g.session.query(
                Group.id, Group.label)
            .filter(Group.id.in_(group_ids))
            .all())
        self.group_id.choices = [('', '')] + [
            (group.id, group.label) for group in groups]

    label = StringField('Nom', [DataRequired()])
    login = StringField('Identifiant', [DataRequired()])
    password = StringField('Mot de passe', [DataRequired()])
    notes = StringField('Notes', [Optional()])
    group_id = SelectField(
        'Groupe', [Optional()],
        coerce=lambda value: int(value) if value else None)


class SharePasswordForm(Form):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        group_ids = [
            group.id
            for group in g.session.query(User).get(session['user_id']).groups]
        groups = (
            g.session.query(
                Group.id, Group.label)
            .filter(Group.id.in_(group_ids))
            .all())
        self.group_ids.choices = [(group.id, group.label) for group in groups]

    group_ids = SelectMultipleField(
        'Groupes', [Optional()],
        option_widget=CheckboxInput(), widget=ListWidget(prefix_label=False),
        coerce=lambda value: int(value) if value else None)


class UserForm(Form):
    login = StringField('Identifiant', [DataRequired(), mail_validator])
    password = PasswordField('Mot de passe', [DataRequired()])


class UserGroupForm(Form):
    mail = StringField('Mail', [DataRequired(), mail_validator])
