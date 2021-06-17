from os import error
from flask import Flask, render_template, url_for, redirect
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_wtf.recaptcha import validators
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


app = Flask(__name__)
app.config["SECRET_KEY"] = "ThisIsASecretKey!" # You should change in production.
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

    def __repr__(self):
        return f"<User {self.username}>"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField("username", validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField("password", validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField("remember me")


class RegistrationForm(FlaskForm):
    email       = StringField("email", validators=[InputRequired(), Email(message="Invalid email"), Length(max=50)])
    username    = StringField("username", validators=[InputRequired(), Length(min=4, max=20)])
    password    = PasswordField("password", validators=[InputRequired(), Length(min=8, max=80)])


@app.route("/")
@login_required
def index():
    return render_template("index.html", name=current_user.username)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for("index"))
        error = "Wrong username or password!"
        return render_template("login.html", form=form, error=error)

    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method="sha256")
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect("login")
        
    return render_template("signup.html", form=form)

if __name__ == "__main__":
    app.run(debug=True) # Turn off when production