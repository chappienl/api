from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL, ValidationError, Email, email_validator
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


def my_email_check(form, field):
    dat = field.data
    if "@" not in dat:
        raise ValidationError("Not a valid email address")
    elif "." not in dat:
        raise ValidationError("Not a valid email address")


def password_data(min=10, max=25):
    message = 'Must be between %d and %d characters long' % (min, max)
    message2 = 'Must contain a number and a special character'

    def _validate(form, field):
        l = field.data and len(field.data) or 0
        if l < min or max != -1 and l > max:
            raise ValidationError(message)
        special_char = '""!@#$%^&*()-+?_=,<>/""'
        if not any(c in special_char for c in field.data):
            raise(ValidationError(message2))
        num = '1234567890'
        if not any(c in num for c in field.data):
            raise(ValidationError(message2))
    return _validate


# TODO: Create a RegisterForm to register new users
class RegisterForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), my_email_check])
    password = PasswordField("Password", validators=[DataRequired(), password_data(min=10)])
    repeat_password = PasswordField("Re-enter Password", validators=[DataRequired(), password_data(min=10)])
    username = StringField("Username", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up")




# TODO: Create a LoginForm to login existing users
class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), my_email_check])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


# TODO: Create a CommentForm so users can leave comments below posts
class CommentForm(FlaskForm):
    message = CKEditorField("Message", validators=[DataRequired()])
    submit = SubmitField("Send")