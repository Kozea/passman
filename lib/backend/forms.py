from wtforms import Form, PasswordField, StringField
from wtforms.validators import DataRequired, Optional


class GroupForm(Form):
    label = StringField('Nom', [DataRequired()])


class PasswordForm(Form):
    label = StringField('Nom', [DataRequired()])
    login = StringField('Identifiant', [DataRequired()])
    password = StringField('Mot de passe', [DataRequired()])
    notes = StringField('Notes', [Optional()])


class UserForm(Form):
    login = StringField('Identifiant', [DataRequired()])
    password = PasswordField('Mot de passe', [DataRequired()])


class UserGroupForm(Form):
    mail = StringField('Mail', [DataRequired()])
