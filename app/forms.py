from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, BooleanField, SubmitField, HiddenField, SelectField, RadioField
from wtforms.fields import DateField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, Length, Regexp


class EditProfileForm(FlaskForm):

    email = HiddenField('email', validators=[DataRequired(), Email()])

    submit = SubmitField('Submit')

    # Initialise Form with user details and role details (roles assigned to user are in user.roles)
    def __init__(self, original_username, roles_available, roles, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.roles_available = roles_available
        self.roles = roles


class FindUsersForm(FlaskForm):

    submit = SubmitField('Submit')

