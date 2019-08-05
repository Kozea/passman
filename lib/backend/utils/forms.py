from wtforms import Form, PasswordField, StringField
from wtforms.validators import DataRequired, Optional, ValidationError


def mail_validator(form, field):
    if '@' not in field.data:
        raise ValidationError('Mail invalide')


class GroupForm(Form):
    label = StringField('Nom', [DataRequired()])


class PasswordForm(Form):
    label = StringField('Nom', [DataRequired()])
    login = StringField('Identifiant', [DataRequired()])
    password = StringField('Mot de passe', [DataRequired()])
    notes = StringField('Notes', [Optional()])


class UserForm(Form):
    login = StringField('Identifiant', [DataRequired(), mail_validator])
    password = PasswordField('Mot de passe', [DataRequired()])


class UserGroupForm(Form):
    mail = StringField('Mail', [DataRequired(), mail_validator])
