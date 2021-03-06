from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

login_manager = LoginManager()
SECRET_KEY = os.environ.get("SECRET_KEY")
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

login_manager.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    "DATABASE_URL", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    posts = relationship("BlogPost", back_populates="author",
                         order_by="BlogPost.date")
    comments = relationship(
        "Comment", back_populates="comment_author", order_by="BlogPost.date")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship(
        "Comment", back_populates="parent_post", order_by="BlogPost.date")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    comment_author = relationship("User", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


db.create_all()


@login_manager.user_loader
def load_user(id):
    return User.query.get(id)


def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user_id = current_user.id
        if user_id == 1:
            return function(*args, **kwargs)
        else:
            return abort(403)
    return wrapper


@app.route('/')
def get_all_posts():

    posts = BlogPost.query.all()
    if current_user.is_authenticated:
        user_id = current_user.id
        # return f"User is {user_id}"
        if user_id == 1:
            return render_template("index.html", all_posts=posts, admin=user_id, logged_in=current_user.is_authenticated)
        else:
            return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if User.query.filter_by(email=register_form.email.data).first():
        # Send flash messsage
        flash("You've already signed up with that email, log in instead!")
        # Redirect to /login route.
        return redirect(url_for('login'))
    if register_form.validate_on_submit():
        password = register_form.password.data
        hashed_password = generate_password_hash(
            password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            email=register_form.email.data,
            password=hashed_password,
            name=register_form.name.data,
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=register_form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        error = None
        password = login_form.password.data
        email = login_form.email.data
        user = User.query.filter_by(email=email).first()
        try:
            user_password = user.password
            if check_password_hash(user_password, password):
                login_user(user)
                # return render_template("index.html", user=user, logged_in=current_user.is_authenticated)
                return redirect(url_for('get_all_posts'))
            elif check_password_hash(user_password, password) == False:
                error = "Password incorect. Pleace try again"
                return render_template("login.html", form=login_form, error=error)
        except AttributeError:
            error = "That email does not exist, please try again."
            return render_template("login.html", form=login_form, error=error)

    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if current_user.is_authenticated:
        if request.method == "POST":
            new_comment = Comment(
                text=form.comment.data,
                comment_author=current_user,
                parent_post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
        user_id = current_user.id
        # return f"User is {user_id}"
        if user_id == 1:
            return render_template("post.html", form=form, post=requested_post, admin=user_id, logged_in=current_user.is_authenticated)
    else:
        if request.method == "POST":
            flash("You need to login to comment!")
            return redirect(url_for('login'))
    return render_template("post.html", form=form, post=requested_post, logged_in=current_user.is_authenticated)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author.name,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))


if __name__ == "__main__":
    app.run(debug=True)
