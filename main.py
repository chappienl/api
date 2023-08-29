from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_wtf import CSRFProtect
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import smtplib
import os

'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

# SET UP EMAIL BY SMTPLIB
# gmail settings --> 2-step ver --> set-up --> 2-step ver again --> App password --> copy password.
my_email = os.environ.get('email')
password = os.environ.get('gmail')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('flask')
ckeditor = CKEditor(app)
Bootstrap5(app)
csrf = CSRFProtect
app.config['BOOTSTRAP_BTN_STYLE'] = 'dark'

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app, size=100, rating='r', default='retro', force_default=False,
                         force_lower=False, use_ssl=False, base_url=None)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URI', "sqlite:///posts.db")
db = SQLAlchemy()
db.init_app(app)



# CONFIGURE TABLES FOR DATABASE ------ BLOGPOST DATA -------
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    def to_dict(self):
        dictionary = {}
        for column in self.__table__.columns:
            dictionary[column.name] = getattr(self, column.name)
        return dictionary


# CONFIGURE TABLES FOR DATABASE ------ USER DATA -------
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)


# CONFIGURE TABLES FOR DATABASE ------ COMMENT DATA -------
class Comment(db.Model):
    __tablename__ = "blog_comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    message = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), nullable=False)

# CONFIGURE TABLES FOR DATABASE ------ CREATE ALL DATABASES -------
with app.app_context():
    db.create_all()


def admin_only(func):
    ''' this function ensures user_id 1 and user_id 2 have wrapper admin rights. '''
    @wraps(func)
    def wrapper_(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.id == 1 or current_user.id == 2:
                return func(*args, **kwargs)
            else:
                return abort(403)
        else:
            return abort(403)
    return wrapper_


def get_user(id):
    ''' function gets user and returns NONE if not found '''
    try:
        name = db.session.get(User, id)
        return name
    except:
        return None


@login_manager.user_loader
def load_user(user_id):
    ''' function to login user '''
    return get_user(user_id)


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['GET', 'POST'])
def register():
    ''' function to register new user, validates with data in database'''
    form = RegisterForm()
    if form.validate_on_submit():
        if db.session.get(User, request.form.get("email")):
            flash("That email is already in our system")
            return render_template("register.html", form=form)
        if db.session.get(User, request.form.get("username")):
            flash("That username is already in our system")
            return render_template("register.html", form=form)
        if request.form.get('password') != request.form.get('repeat_password'):
            flash("Please enter the same passwords")
            return render_template("register.html", form=form)
        new_user = User()
        new_user.name = request.form.get('username')
        new_user.email = request.form.get('email')
        new_user.password = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256', salt_length=8)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template("register.html", form=form)


# TODO: Retrieve a user from the database based on their email, check password is corrects. .
@app.route('/login', methods=['GET', 'POST'])
def login():
    ''' retrieves user data from database, checks password and checks user in. '''
    form = LoginForm()
    if form.validate_on_submit():
        if not db.session.execute(db.select(User).where(User.email == request.form.get('email'))).scalar():
            flash("Email not found in our database")
        if db.session.execute(db.select(User).where(User.email == request.form.get('email'))).scalar():
            user = db.session.execute(db.select(User).where(User.email == request.form.get('email'))).scalar()
            if check_password_hash(user.password, request.form.get('password')):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Invalid password')
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    ''' function to logout'''
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    ''' route to home. returns all posts'''
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    ''' this function shows posts, but also allows for comments. '''
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        new_comment = Comment()
        message = request.form.get('message').replace("<p>", "").replace("</p>", "\n").replace("&amp;", "&").replace("&#39;", "'").replace('&quot;', '"')
        new_comment.message = message
        new_comment.author = current_user.name
        new_comment.post_id = requested_post.id
        new_comment.author_id = current_user.id
        db.session.add(new_comment)
        db.session.commit()
    result = db.session.execute(db.select(Comment))
    comments = result.scalars().all()
    return render_template("post.html", post=requested_post, form=form, comments=comments)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    ''' function to add a post'''
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    ''' function to edit a post'''
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = post.author
        post.id = post.id
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    ''' function to delete a post'''
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/delete_comment/<int:comment_id>")
def delete_comment(comment_id):
    ''' function to delete a comment. Only Admins and author can edit comment. '''
    comment_to_delete = db.get_or_404(Comment, comment_id)
    if not current_user.id == 1 and not current_user.id == 2 and not current_user.id == comment_to_delete.author_id:
        flash("You do not have the rights to perform that action.")
        return redirect(url_for('show_post', post_id=comment_to_delete.post_id))
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=comment_to_delete.post_id))


@app.route("/about")
def about():
    ''' route to about page'''
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    ''' function sends emails from the contact page with SMTPlib'''
    if request.method == "POST":
        data = request.form
        with smtplib.SMTP("smtp.gmail.com", port=587) as connection:
            connection.starttls()
            connection.login(user=my_email, password=password)
            connection.sendmail(
                from_addr=data['email'],
                to_addrs=f"{os.environ.get('to_email')}",
                msg=f"Subject: Contact Post\n\n"
                    f"You've received a message from: {data['name']}\n"
                    f"Message:\n"
                    f"{data['message']}\n\n"
                    f"Name: {data['name']}\n"
                    f"Phone: {data['phone']}\n"
                    f"Email: {data['email']}"
            )
            flash("Your message is send successfully")
        return render_template("contact.html", title="Successfully returned message")
    else:
        return render_template("contact.html", title="Contact Me")



if __name__ == "__main__":
    app.run(debug=False)
