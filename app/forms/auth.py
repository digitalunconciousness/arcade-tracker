"""Authentication and profile forms."""

from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed
from wtforms import (
    BooleanField,
    FileField,
    PasswordField,
    StringField,
    SubmitField,
)
from wtforms.validators import DataRequired, EqualTo, Length


class LoginForm(FlaskForm):
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=2, max=80)]
    )
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")


class RegisterForm(FlaskForm):
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=4, max=80)]
    )
    password = PasswordField(
        "Password", validators=[DataRequired(), Length(min=8)]
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password")],
    )
    submit = SubmitField("Register")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField(
        "Current Password", validators=[DataRequired()]
    )
    new_password = PasswordField(
        "New Password", validators=[DataRequired(), Length(min=8)]
    )
    confirm_password = PasswordField(
        "Confirm New Password",
        validators=[DataRequired(), EqualTo("new_password")],
    )
    submit = SubmitField("Change Password")


class ProfileForm(FlaskForm):
    profile_picture = FileField(
        "Profile Picture",
        validators=[FileAllowed(["jpg", "jpeg", "png", "gif"])],
    )
    submit = SubmitField("Update Profile")
