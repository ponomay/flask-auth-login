from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_idd):
    print('this is executed', user_idd)
    return User.query.get(user_idd)


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
#db.create_all()


@app.route('/')
def home():
    logout_user()
    return render_template("index.html")


@app.route('/register', methods=["POST", "GET"])
def register():
    if request.method == "POST":
        new_user = User(
            email=request.form.get('email'),
            password=generate_password_hash(request.form.get('password'), method='pbkdf2:sha256', salt_length=8),
            name=request.form.get('name'),
        )
        print(new_user.password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('secrets', name=new_user.name))
    return render_template("register.html")


@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST":
        email=request.form.get('email')
        password=request.form.get('password')
        name=request.form.get('name')
        log_user = User.query.filter_by(email=email).first()
        if log_user:
            if check_password_hash(log_user.password, password):
                print('logged_in')
                login_user(log_user)
                print(log_user.is_authenticated)


            else:
                flash("password is not correct")
                return redirect(url_for('login'))
            return redirect(url_for('secrets', name=log_user.name))

        else:
            flash("User do not exists")
            return redirect(url_for('login'))
    return render_template("login.html")


@app.route('/secrets/<name>')
@login_required
def secrets(name):
    print(current_user.name)
    return render_template("secrets.html", name=name)


@app.route('/logout')
def logout():
    pass


@app.route('/download')
@login_required
def download():
    return send_from_directory("static/files/", "cheat_sheet.pdf")





if __name__ == "__main__":
    app.run(debug=True)
